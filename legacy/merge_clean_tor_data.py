import pandas as pd

# Load both scenario files (adjust path if needed)
df_a = pd.read_csv('data/batch_results/Scenario-A-merged_5s.csv')
df_b = pd.read_csv('data/batch_results/Scenario-B-merged_5s.csv')

# Standardize column names (remove leading/trailing spaces)
df_a.columns = df_a.columns.str.strip()
df_b.columns = df_b.columns.str.strip()

# Combine (concat) them together into one DataFrame
df = pd.concat([df_a, df_b], ignore_index=True)

# Standardize labels: mark anything containing 'tor' as 'tor', all others as 'nontor'
df['label'] = df['label'].astype(str).str.lower().str.strip()
df['label'] = df['label'].apply(lambda x: 'tor' if 'tor' in x else 'nontor')

# Drop identifier columns (keep only numeric features and label)
drop_cols = ['Source IP', 'Destination IP']
df = df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore')

# Keep only numeric columns + label
num_cols = df.select_dtypes(include=['number']).columns.tolist()
df = df[num_cols + ['label']]

# Save the cleaned, merged file for training
outpath = 'data/batch_results/tor_nontor_merged_features.csv'
df.to_csv(outpath, index=False)
print(f'Merged and cleaned file saved to: {outpath}')
