import pandas as pd
import glob
import os

labels_df = pd.read_csv("data/pcap_files/pcap_labels.csv")
labels_dict = dict(zip(labels_df['filename'], labels_df['label']))

csv_files = glob.glob("data/batch_results/*_features.csv")
dfs = []

for f in csv_files:
    df = pd.read_csv(f)
    if not df.empty:
        pcap_name = os.path.basename(f).replace("_features.csv", ".pcap")
        df['label'] = labels_dict.get(pcap_name, "unknown")
        dfs.append(df)

if dfs:
    combined_df = pd.concat(dfs, ignore_index=True)
    combined_df.to_csv("data/batch_results/all_tor_non_tor_combined.csv", index=False)
    print(f"Combined {len(combined_df)} rows from {len(dfs)} files")
else:
    print("No data found.")
