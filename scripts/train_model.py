import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from tqdm import tqdm

# Function to print a status message with a separator
def print_status(message):
    print("\n" + "=" * 50)
    print(message)
    print("=" * 50 + "\n")

# Step 1: Load the preprocessed dataset
print_status("Step 1: Loading the preprocessed dataset...")
data = pd.read_csv("data/preprocessed_data.csv")

# Reduce the dataset size to 50%
data = data.sample(frac=0.5, random_state=42)  # Use 50% of the data
print("Dataset loaded successfully!")
print("Dataset shape:", data.shape)

# Step 2: Split features and labels
print_status("Step 2: Splitting features and labels...")
X = data.drop(columns=['Label'])  # Features
y = data['Label']                 # Labels
print("Features shape:", X.shape)
print("Labels shape:", y.shape)

# Step 3: Inspect the labels
print_status("Step 3: Inspecting labels...")
print("Unique labels:", y.unique())
print("Label data type:", y.dtype)

# Step 4: Convert labels to discrete classes
print_status("Step 4: Converting labels to discrete classes...")
y = y.round().astype(int)  # Option 1: Round and convert to integers
# y = pd.cut(y, bins=5, labels=False)  # Option 2: Bin continuous values
# y = y.astype(int)  # Option 3: Convert to integers
print("Labels after conversion:", y.unique())

# Step 5: Split into training and testing sets
print_status("Step 5: Splitting into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("Training set shape:", X_train.shape)
print("Testing set shape:", X_test.shape)

# Step 6: Train the Random Forest model
print_status("Step 6: Training the Random Forest model...")
model = RandomForestClassifier(n_estimators=50, max_depth=10, n_jobs=-1, random_state=42)

# Add a progress bar for training
print("Starting training...")
with tqdm(total=100, desc="Training Progress") as pbar:
    model.fit(X_train, y_train)
    pbar.update(100)  # Mark training as complete
print("Training completed!")

# Step 7: Evaluate the model
print_status("Step 7: Evaluating the model...")
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Step 8: Save the trained model
print_status("Step 8: Saving the trained model...")
joblib.dump(model, "models/random_forest_model.pkl")
print("Model saved to 'models/random_forest_model.pkl'")

print_status("Script execution completed!")