import pandas as pd
import numpy as np
import joblib

# Step 1: Load the saved model
model = joblib.load('tor_detection_model.pkl')

# Step 2: Load new data (CSV)
df_new = pd.read_csv('data/new_traffic/new_data.csv')

# Step 3: Standardize column names (strip whitespace)
df_new.columns = df_new.columns.str.strip()

# Step 4: Remove non-numeric columns (except those in training data)
# Replace with your actual feature columns (from training)
feature_columns = [col for col in df_new.columns if col != 'label' and pd.api.types.is_numeric_dtype(df_new[col])]
X_new = df_new[feature_columns]

# Step 5: Replace inf, -inf with NaN, then fill NaN with median
X_new = X_new.replace([np.inf, -np.inf], np.nan)
X_new = X_new.fillna(X_new.median(numeric_only=True))

# Step 6: Make predictions
predictions = model.predict(X_new)

# Step 7: Save or print results
df_new['prediction'] = predictions
df_new.to_csv('data/new_traffic/predictions.csv', index=False)
print("Predictions saved to data/new_traffic/predictions.csv")
