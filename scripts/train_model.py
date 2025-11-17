import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Load the dataset
df = pd.read_csv('data/batch_results/all_tor_non_tor_combined.csv')

# Feature engineering
def extract_features(row):
    features = {}
    features['packet_count'] = row['packet_count']
    features['duration'] = row['duration']
    features['total_bytes'] = row['total_bytes']
    features['avg_packet_size'] = row['avg_packet_size']
    features['is_guard'] = 1 if row['is_guard'] == True else 0
    features['is_exit'] = 1 if row['is_exit'] == True else 0
    return features

# Extract features
X = pd.DataFrame([extract_features(row) for _, row in df.iterrows()])
y = df['label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
