import pandas as pd

# Load pcap labels
labels = pd.read_csv('data/pcap_files/pcap_labels.csv')

# Feature files to process
feature_files = [
    'data/batch_results/real_capture_features.csv',
    'data/batch_results/sample_features.csv',
    'data/batch_results/live_20251109_202230_features.csv',
    'data/batch_results/live_20251109_202006_features.csv',
    'data/batch_results/live_20251109_202113_features.csv',
    'data/batch_results/live_20251109_213501_features.csv',
]

pcap_names = [
    'real_capture',
    'sample',
    'live_20251109_202230',
    'live_20251109_202006',
    'live_20251109_202113',
    'live_20251109_213501',
]

for feature_file, pcap_name in zip(feature_files, pcap_names):
    df = pd.read_csv(feature_file)
    label_row = labels[labels['filename'] == pcap_name + '.pcap']
    if not label_row.empty:
        df['label'] = label_row['label'].values[0]
    else:
        df['label'] = 'nontor'  # default
    df.to_csv(feature_file, index=False)
    print(f"Added label to {feature_file}")
