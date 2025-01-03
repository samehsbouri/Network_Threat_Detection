import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the expected features to match capture_traffic.py
EXPECTED_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
    'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

def preprocess_captured_data(df):
    """Preprocess the captured traffic data"""
    try:
        # Create a copy of input data
        features = df.copy()
        
        # Ensure all expected features are present
        for feature in EXPECTED_FEATURES:
            if feature not in features.columns:
                features[feature] = 0
        
        # Keep only expected features
        features = features[EXPECTED_FEATURES]
        
        # Convert all numeric columns
        for col in features.columns:
            features[col] = pd.to_numeric(features[col], errors='coerce')
        
        # Fill missing values
        features = features.fillna(0)
        
        # Replace infinite values
        features = features.replace([np.inf, -np.inf], 0)
        
        # Keep original features before scaling
        features_original = features.copy()
        
        # Scale features
        logging.info("Scaling features...")
        scaler = StandardScaler()
        features_scaled = pd.DataFrame(
            scaler.fit_transform(features),
            columns=features.columns
        )
        
        return features_scaled, features_original
        
    except Exception as e:
        logging.error(f"Error in preprocessing: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        return None, None

def create_default_model(features):
    """Create a default random forest model"""
    try:
        logging.info("Creating default random forest model...")
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Create dummy labels (all benign)
        labels = np.zeros(len(features))
        
        # Train the model
        model.fit(features, labels)
        return model
        
    except Exception as e:
        logging.error(f"Error creating default model: {str(e)}")
        return None

def analyze_packets(input_file, model_file, output_file):
    """Analyze captured packets and detect potential threats"""
    try:
        # Read captured data
        logging.info(f"Reading captured data from {input_file}")
        df = pd.read_csv(input_file)
        
        logging.info(f"Data shape: {df.shape}")
        logging.info(f"Columns: {df.columns.tolist()}")
        
        # Preprocess data
        logging.info("Preprocessing data...")
        features_scaled, features_original = preprocess_captured_data(df)
        
        if features_scaled is None:
            raise ValueError("Failed to preprocess data")
        
        # Load or create model
        logging.info("Loading/creating model...")
        if os.path.exists(model_file):
            model = joblib.load(model_file)
            logging.info("Loaded existing model")
        else:
            model = create_default_model(features_scaled)
            if model is None:
                raise ValueError("Failed to create model")
            joblib.dump(model, model_file)
            logging.info("Created and saved new model")
        
        # Make predictions
        logging.info("Making predictions...")
        predictions = model.predict(features_scaled)
        
        # Calculate additional metrics
        flow_duration = features_original['Flow Duration']
        packets_per_sec = features_original['Flow Packets/s']
        bytes_per_sec = features_original['Flow Bytes/s']
        
        # Create alerts DataFrame
        alerts_df = pd.DataFrame({
            'timestamp': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
            'prediction': predictions,
            'flow_duration': flow_duration,
            'packets_per_second': packets_per_sec,
            'bytes_per_second': bytes_per_sec,
            'destination_port': features_original['Destination Port'],
            'active_mean': features_original['Active Mean'],
            'idle_mean': features_original['Idle Mean'],
            'fwd_packets': features_original['Total Fwd Packets'],
            'bwd_packets': features_original['Total Backward Packets'],
            'avg_packet_size': features_original['Average Packet Size']
        })
        
        # Add threat severity
        alerts_df['severity'] = pd.cut(
            alerts_df['bytes_per_second'],
            bins=[-np.inf, 1000, 10000, np.inf],
            labels=['Low', 'Medium', 'High']
        )
        
        # Filter alerts (prediction == 1 for threats)
        alerts_df = alerts_df[alerts_df['prediction'] == 1]
        
        # Save alerts
        alerts_df.to_csv(output_file, index=False)
        logging.info(f"Analysis complete. Found {len(alerts_df)} potential threats.")
        
        # Additional statistics
        total_flows = len(df)
        threat_ratio = len(alerts_df) / total_flows if total_flows > 0 else 0
        average_severity = alerts_df['severity'].value_counts().to_dict()
        
        logging.info(f"Threat ratio: {threat_ratio:.2%}")
        logging.info(f"Severity distribution: {average_severity}")
        
        return True
        
    except Exception as e:
        logging.error(f"Error in analyze_packets: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        return False

def validate_model_performance(model, features, labels):
    """Validate model performance (if labels are available)"""
    try:
        from sklearn.metrics import accuracy_score, precision_score, recall_score
        
        predictions = model.predict(features)
        
        metrics = {
            'accuracy': accuracy_score(labels, predictions),
            'precision': precision_score(labels, predictions, zero_division=0),
            'recall': recall_score(labels, predictions, zero_division=0)
        }
        
        logging.info("Model performance metrics:")
        for metric, value in metrics.items():
            logging.info(f"{metric}: {value:.4f}")
            
        return metrics
        
    except Exception as e:
        logging.error(f"Error validating model: {str(e)}")
        return None

if __name__ == "__main__":
    # Test paths
    input_file = "data/captured_traffic.csv"
    model_file = "models/random_forest_model.pkl"
    output_file = "data/alerts.csv"
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(model_file), exist_ok=True)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    if os.path.exists(input_file):
        success = analyze_packets(input_file, model_file, output_file)
        if success:
            logging.info("Analysis completed successfully")
        else:
            logging.error("Analysis failed")
    else:
        logging.error(f"Input file {input_file} not found")