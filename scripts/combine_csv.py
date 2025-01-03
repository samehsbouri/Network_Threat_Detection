import os
import pandas as pd

# Path to the folder containing the CSV files
data_folder = "data/CICIDS2017/"

# List all CSV files in the folder
csv_files = [f for f in os.listdir(data_folder) if f.endswith('.csv')]

# Load and concatenate all CSV files
dataframes = []
for file in csv_files:
    file_path = os.path.join(data_folder, file)
    df = pd.read_csv(file_path)
    dataframes.append(df)

# Combine all DataFrames into one
combined_data = pd.concat(dataframes, ignore_index=True)

# Save the combined DataFrame to a single CSV file
combined_data.to_csv("data/combined_data.csv", index=False)

print("Combined dataset saved to 'data/combined_data.csv'")