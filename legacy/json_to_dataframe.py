import sys
import json
import pandas as pd

def flatten_timing_patterns(data):
    rows = []
    for flow in data.get("timing_patterns", []):
        row = flow.copy()
        # Optionally: flatten any list fields (e.g., take first N, mean, or join as string)
        row['inter_packet_times'] = ','.join(map(str, row['inter_packet_times']))
        row['packet_sizes'] = ','.join(map(str, row['packet_sizes']))
        row['directions'] = ','.join(map(str, row['directions']))
        # You can add additional meta-fields from top level, e.g. pcap filename
        row['pcap_file'] = data.get('pcap_file')
        rows.append(row)
    return rows

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 json_to_dataframe.py <input_json> <output_csv>")
        sys.exit(1)
    input_json = sys.argv[1]
    output_csv = sys.argv[2]

    with open(input_json, "r") as f:
        data = json.load(f)
    rows = flatten_timing_patterns(data)
    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    print(f"CSV saved to {output_csv}, {len(df)} rows")
