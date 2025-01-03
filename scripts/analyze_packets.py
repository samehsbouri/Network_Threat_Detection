import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib
import os

def convert_timestamp(ts):
    try:
        return float(ts)
    except ValueError:
        return 0

def preprocess_captured_data(df):
    try:
        # Convert timestamp to numeric
        print("Converting timestamps...")
        df['timestamp'] = df['timestamp'].apply(convert_timestamp)
        
        # Convert numeric columns
        numeric_columns = ['frame_length', 'protocol', 'src_port', 'dst_port', 'ip_length']
        for col in numeric_columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Create features matching CICIDS2017 dataset
        print("Creating features...")
        
        # Group by source and destination IP
        flow_groups = df.groupby(['source_ip', 'dest_ip'])
        
        # Initialize features DataFrame with multi-index
        features = pd.DataFrame(index=flow_groups.groups.keys())
        features.index.names = ['source_ip', 'dest_ip']
        
        # Basic flow features
        features['Destination Port'] = flow_groups['dst_port'].first()
        features['Flow Duration'] = flow_groups['timestamp'].apply(lambda x: x.max() - x.min())
        features['Total Fwd Packets'] = flow_groups.size()
        features['Total Backward Packets'] = flow_groups.size()
        
        # Packet length features
        features['Total Length of Fwd Packets'] = flow_groups['frame_length'].sum()
        features['Total Length of Bwd Packets'] = flow_groups['frame_length'].sum()
        features['Fwd Packet Length Max'] = flow_groups['frame_length'].max()
        features['Fwd Packet Length Min'] = flow_groups['frame_length'].min()
        features['Fwd Packet Length Mean'] = flow_groups['frame_length'].mean()
        features['Fwd Packet Length Std'] = flow_groups['frame_length'].std().fillna(0)
        
        # Backward packet length features
        features['Bwd Packet Length Max'] = flow_groups['frame_length'].max()
        features['Bwd Packet Length Min'] = flow_groups['frame_length'].min()
        features['Bwd Packet Length Mean'] = flow_groups['frame_length'].mean()
        features['Bwd Packet Length Std'] = flow_groups['frame_length'].std().fillna(0)
        
        # Flow rate features
        time_window = df['timestamp'].max() - df['timestamp'].min()
        if time_window == 0:
            time_window = 1
        features['Flow Bytes/s'] = features['Total Length of Fwd Packets'] / time_window
        features['Flow Packets/s'] = features['Total Fwd Packets'] / time_window
        
        # Add all other features with default values
        default_features = [
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
            'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
            'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
            'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
            'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
            'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
            'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
        
        for feature in default_features:
            if feature not in features.columns:
                features[feature] = 0

        # Calculate some derived features
        features['Min Packet Length'] = flow_groups['frame_length'].min()
        features['Max Packet Length'] = flow_groups['frame_length'].max()
        features['Packet Length Mean'] = flow_groups['frame_length'].mean()
        features['Packet Length Std'] = flow_groups['frame_length'].std().fillna(0)
        features['Packet Length Variance'] = features['Packet Length Std'] ** 2
        features['Average Packet Size'] = features['Packet Length Mean']
        
        # Handle any remaining infinite values
        features = features.replace([np.inf, -np.inf], np.nan)
        features = features.fillna(0)
        
        print("Features created:", features.columns.tolist())
        print("Feature statistics:")
        print(features.describe())
        
        # Normalize features while preserving the index
        print("Normalizing features...")
        scaler = StandardScaler()
        features_array = scaler.fit_transform(features)
        features_scaled = pd.DataFrame(
            features_array, 
            index=features.index, 
            columns=features.columns
        )
        
        return features_scaled, features
        
    except Exception as e:
        print(f"Error in preprocessing: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return None, None

def analyze_packets(input_file, model_file, output_file):
    try:
        # Read captured data
        print(f"Reading captured data from {input_file}")
        df = pd.read_csv(input_file)
        
        print("Initial data shape:", df.shape)
        print("Columns:", df.columns.tolist())
        print("Data types:")
        print(df.dtypes)
        
        # Preprocess captured data
        print("Preprocessing captured data...")
        features_scaled, features_original = preprocess_captured_data(df)
        
        if features_scaled is None:
            raise ValueError("Failed to preprocess data")
        
        # Load the model
        print(f"Loading model from {model_file}")
        model = joblib.load(model_file)
        
        # Get the expected feature names from the model
        try:
            expected_features = model.feature_names_in_
        except AttributeError:
            expected_features = features_scaled.columns
        
        # Ensure features are in the correct order
        features_scaled = features_scaled[expected_features]
        
        # Verify feature alignment
        print("\nVerifying features alignment...")
        print("Expected features:", list(expected_features))
        print("Actual features:", list(features_scaled.columns))
        
        # Make predictions
        print("Making predictions...")
        predictions = model.predict(features_scaled)
        
        # Create alerts DataFrame
        alerts_df = pd.DataFrame({
            'timestamp': df.groupby(['source_ip', 'dest_ip'])['timestamp'].first(),
            'prediction': predictions,
            'flow_duration': features_original['Flow Duration'],
            'packets_per_second': features_original['Flow Packets/s'],
            'bytes_per_second': features_original['Flow Bytes/s']
        }, index=features_scaled.index)
        
        # Reset index to convert multi-index to columns
        alerts_df = alerts_df.reset_index()
        
        # Filter only alerts (prediction == 1)
        alerts_df = alerts_df[alerts_df['prediction'] == 1]
        
        # Save alerts
        alerts_df.to_csv(output_file, index=False)
        print(f"Analysis complete. Found {len(alerts_df)} potential threats.")
        return True
        
    except Exception as e:
        print(f"Error in analyze_packets: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == "__main__":
    # Test the functions
    input_file = "data/captured_traffic.csv"
    model_file = "models/random_forest_model.pkl"
    output_file = "data/alerts.csv"
    
    if os.path.exists(input_file):
        analyze_packets(input_file, model_file, output_file)
    else:
        print(f"Input file {input_file} not found")