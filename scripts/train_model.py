import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
from tqdm import tqdm
import matplotlib.pyplot as plt
import seaborn as sns
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to print a status message with a separator
def print_status(message):
    logging.info("\n" + "=" * 50)
    logging.info(message)
    logging.info("=" * 50 + "\n")

# Step 1: Load the preprocessed dataset
print_status("Step 1: Loading the preprocessed dataset...")
data = pd.read_csv("data/preprocessed_data.csv")

# Reduce the dataset size to 50% (optional, for faster training)
data = data.sample(frac=0.5, random_state=42)
logging.info("Dataset loaded successfully!")
logging.info(f"Dataset shape: {data.shape}")

# Step 2: Split features and labels
print_status("Step 2: Splitting features and labels...")
X = data.drop(columns=['Label'])
y = data['Label']
logging.info(f"Features shape: {X.shape}")
logging.info(f"Labels shape: {y.shape}")

# Step 3: Inspect the labels
print_status("Step 3: Inspecting labels...")
logging.info(f"Unique labels: {y.unique()}")
logging.info(f"Label data type: {y.dtype}")

# Step 4: Convert labels to discrete classes
print_status("Step 4: Converting labels to discrete classes...")
y = y.round().astype(int)
logging.info(f"Labels after conversion: {y.unique()}")

# Step 5: Split into training and testing sets
print_status("Step 5: Splitting into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
logging.info(f"Training set shape: {X_train.shape}")
logging.info(f"Testing set shape: {X_test.shape}")

# Step 6: Train the Random Forest model
print_status("Step 6: Training the Random Forest model...")
model = RandomForestClassifier(
    n_estimators=50,
    max_depth=10,
    n_jobs=-1,
    random_state=42,
    class_weight='balanced'  # Handle class imbalance
)

# Add a progress bar for training
logging.info("Starting training...")
with tqdm(total=100, desc="Training Progress") as pbar:
    model.fit(X_train, y_train)
    pbar.update(100)
logging.info("Training completed!")

# Step 7: Evaluate the model
print_status("Step 7: Evaluating the model...")
y_pred = model.predict(X_test)
logging.info(f"Accuracy: {accuracy_score(y_test, y_pred)}")
logging.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")

# Generate confusion matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()

# Step 8: Save the trained model
print_status("Step 8: Saving the trained model...")
joblib.dump(model, "models/random_forest_model.pkl")
logging.info("Model saved to 'models/random_forest_model.pkl'")

print_status("Script execution completed!")