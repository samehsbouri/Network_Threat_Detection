import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np

# Load the combined dataset
combined_data = pd.read_csv("data/combined_data.csv")

# Strip leading/trailing spaces from column names
combined_data.columns = combined_data.columns.str.strip()

# Print column names for debugging
print("Columns in the dataset:", combined_data.columns.tolist())

# Handle missing values
combined_data = combined_data.dropna()

# Check for infinite values and replace them with NaN
combined_data.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop rows with NaN values (if any remain)
combined_data = combined_data.dropna()

# Encode categorical labels (e.g., "BENIGN", "DDoS")
label_encoder = LabelEncoder()
combined_data['Label'] = label_encoder.fit_transform(combined_data['Label'])

# Normalize numerical features
scaler = StandardScaler()

# Select numerical features (exclude the 'Label' column)
numerical_features = combined_data.select_dtypes(include=['float64', 'int64']).columns
numerical_features = numerical_features[numerical_features != 'Label']  # Exclude the label column

# Check for extremely large values
print("Max values in numerical features:")
print(combined_data[numerical_features].max())

# Normalize the numerical features
combined_data[numerical_features] = scaler.fit_transform(combined_data[numerical_features])

# Save the preprocessed dataset
combined_data.to_csv("data/preprocessed_data.csv", index=False)

print("Preprocessed dataset saved to 'data/preprocessed_data.csv'")