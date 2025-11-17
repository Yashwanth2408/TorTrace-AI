import os
import subprocess
import glob

pcap_dir = "data/pcap_files"
out_dir = "data/batch_results"
db_path = "data/tor_relays.db"

os.makedirs(out_dir, exist_ok=True)

for pcap in glob.glob(f"{pcap_dir}/*.pcap"):
    out_file = f"{out_dir}/{os.path.basename(pcap).replace('.pcap', '_analysis.json')}"
    cmd = [
        "python3", "traffic_analysis/pcap_analyzer.py",
        "--pcap", pcap,
        "--out", out_file,
        "--db", db_path
    ]
    print(f"Analyzing {pcap}...")
    subprocess.run(cmd)
