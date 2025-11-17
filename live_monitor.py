import os
import time
import subprocess
from datetime import datetime

PCAP_DIR = 'data/pcap_files'
CAPTURE_INTERFACE = 'eth0'
CAPTURE_DURATION = 60      # Capture window in seconds (e.g. 60s = 1 min)
BATCH_SCRIPT = 'batch_analyzer.py'

def capture_live_pcap():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = os.path.join(PCAP_DIR, f'live_{timestamp}.pcap')
    print(f'\n[+] Capturing {CAPTURE_DURATION}s of live traffic to {pcap_file}')
    tcpdump_cmd = [
    'sudo', 'tcpdump',
    '-i', CAPTURE_INTERFACE,
    '-w', pcap_file,
    '-G', str(CAPTURE_DURATION),
    '-W', '1',
    'tcp'
    ]

    subprocess.run(tcpdump_cmd)
    print('[+] Capture complete')
    return pcap_file

def run_batch_analysis():
    print('[+] Running batch analysis for all PCAPs...')
    subprocess.run(['python3', BATCH_SCRIPT])
    print('[+] Batch analysis complete')

def main():
    print('[MONITOR] Live traffic capture and automated analysis')
    print('Press Ctrl+C to stop.\n')
    os.makedirs(PCAP_DIR, exist_ok=True)
    while True:
        pcap = capture_live_pcap()
        run_batch_analysis()
        print('[MONITOR] Sleeping for 5 seconds before next capture...\n')
        time.sleep(5)

if __name__ == '__main__':
    main()
