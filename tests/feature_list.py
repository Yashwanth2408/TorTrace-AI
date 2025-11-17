import joblib
import pandas as pd

# Change filepath as needed
model = joblib.load('data/batch_results/tor_detection_model.pkl')

# If you saved feature_names explicitly when training:
try:
    feature_list = model.feature_names_in_  # works for most sklearn models post 1.0+
except AttributeError:
    # Fallback for your pipeline: use the columns of the DataFrame used for training
    df = pd.read_csv("path/to/a representative CSV used for model fitting.csv")
    feature_list = df.columns.tolist()
print(feature_list)
