import pandas as pd
import numpy as np
import shutil

# 1. Make a safety copy
shutil.copyfile(
    'data/batch_results/Scenario-A-merged_5s.csv',
    'data/batch_results/scenario_A_cleaned.csv'
)

# 2. Load the data
raw_df = pd.read_csv('data/batch_results/scenario_A_cleaned.csv')

# 3. Select only numeric columns + label
numeric_df = raw_df.select_dtypes(include=[np.number])
if 'label' not in numeric_df.columns:
    numeric_df['label'] = raw_df['label']

# 4. Standardize labels
numeric_df['label'] = numeric_df['label'].astype(str).str.lower().str.strip()
numeric_df = numeric_df[numeric_df['label'].isin(['tor', 'nontor'])]

# 5. Fill missing numeric values with median
for col in numeric_df.select_dtypes(include=[np.number]).columns:
    median = numeric_df[col].median()
    numeric_df[col] = numeric_df[col].fillna(median)

# 6. Drop rows with missing label, just in case
numeric_df = numeric_df.dropna(subset=['label'])

# 7. Save for model training
numeric_df.to_csv('data/batch_results/tor_nontor_features.csv', index=False)
print('Cleaned data saved as data/batch_results/tor_nontor_features.csv')
