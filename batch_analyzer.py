import os
import json
import subprocess
from datetime import datetime
import csv
import time
from concurrent.futures import ProcessPoolExecutor, as_completed


PCAP_DIR = 'data/pcap_files'
RESULTS_DIR = 'data/batch_results'
ALERT_LOG = 'data/alert_log.json'
PERF_METRICS = 'data/perf_metrics.json'
ALERT_THRESHOLD = 50.0  # Confidence % for triggering alert
ANALYZER_SCRIPT = 'traffic_analysis/pcap_analyzer.py'
CORRELATOR_SCRIPT = 'correlation/timing_correlator.py'
FINGERPRINTER_SCRIPT = 'ml_models/website_fingerprinter.py'
GNN_SCRIPT = 'ml_models/gnn_guard_predictor.py'


os.makedirs(RESULTS_DIR, exist_ok=True)


def run_command(args):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Process timed out", -1


def wait_for_file(filepath, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            time.sleep(0.5)
            return True
        time.sleep(0.1)
    return False


def check_tor_flows(analysis_file):
    try:
        with open(analysis_file, 'r') as f:
            data = json.load(f)
            return data.get('tor_flows', 0) > 0
    except:
        return False


def log_alerts(pcap_name, guard_results, alert_log=ALERT_LOG):
    triggered = []
    for r in guard_results:
        try:
            conf = float(r.get('confidence') or r.get('Confidence') or 0)
        except Exception:
            conf = 0
        if conf >= ALERT_THRESHOLD:
            triggered.append({
                "pcap": pcap_name,
                "nickname": r.get('nickname') or r.get('Relay Nickname'),
                "confidence": conf,
                "ip": r.get('relay_ip') or r.get('IP Address')
            })
    if triggered:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "alerts": triggered
        }
        if os.path.exists(alert_log):
            with open(alert_log, "r") as f:
                alerts = json.load(f)
        else:
            alerts = []
        alerts.append(entry)
        with open(alert_log, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"\n🚨 [ALERT] High-confidence guard node(s) detected in {pcap_name}:")
        for a in triggered:
            print(f"    > {a['nickname']} ({a['ip']}) [{a['confidence']}%]")
    return triggered


def analyze_pcap(pcap_file):
    try:
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        print(f"\nAnalyzing {pcap_file} ...")
        analyzer_out = os.path.join(RESULTS_DIR, f'{base_name}_analysis.json')
        cmd_analyzer = ['python3', ANALYZER_SCRIPT, '--pcap', pcap_file, '--out', analyzer_out]
        out, err, code = run_command(cmd_analyzer)
        if code != 0:
            print(f"PCAP analyzer failed:\nSTDOUT:\n{out}\nSTDERR:\n{err}")
            return None
        if not wait_for_file(analyzer_out):
            print(f"Error: Analysis file not created: {analyzer_out}")
            return None
        print(f"PCAP analysis done, results saved to {analyzer_out}")

        has_tor_flows = check_tor_flows(analyzer_out)
        if not has_tor_flows:
            print(f"No Tor flows detected in {pcap_file}, skipping downstream analysis")
            return {
                'pcap': pcap_file,
                'analysis': analyzer_out,
                'timing': None,
                'fingerprint': None,
                'gnn': None,
                'has_tor_flows': False
            }

        correlator_out = os.path.join(RESULTS_DIR, f'{base_name}_timing.json')
        cmd_corr = ['python3', CORRELATOR_SCRIPT, '--input', analyzer_out, '--output', correlator_out]
        out, err, code = run_command(cmd_corr)
        if code != 0:
            print(f"Timing correlator failed:\nSTDOUT:\n{out}\nSTDERR:\n{err}")
        else:
            print(f"Timing correlation done, results saved to {correlator_out}")

        fingerprint_out = os.path.join(RESULTS_DIR, f'{base_name}_fingerprint.json')
        cmd_fp = ['python3', FINGERPRINTER_SCRIPT, '--input', analyzer_out, '--output', fingerprint_out]
        out, err, code = run_command(cmd_fp)
        if code != 0:
            print(f"Fingerprinting failed:\nSTDOUT:\n{out}\nSTDERR:\n{err}")
        else:
            print(f"Website fingerprinting done, results saved to {fingerprint_out}")

        gnn_out = os.path.join(RESULTS_DIR, f'{base_name}_gnn.json')
        cmd_gnn = ['python3', GNN_SCRIPT, '--db', 'data/tor_relays.db', '--input', analyzer_out, '--output', gnn_out]
        out, err, code = run_command(cmd_gnn)
        if code != 0:
            print(f"GNN predictor failed:\nSTDOUT:\n{out}\nSTDERR:\n{err}")
            return None
        print(f"GNN guard prediction done, results saved to {gnn_out}")

        # Real-time alert check after GNN prediction
        try:
            with open(gnn_out, 'r') as f:
                gnn_data = json.load(f)
            guard_results = gnn_data.get('predictions', [])[:3]
            log_alerts(pcap_file, guard_results)
        except Exception as e:
            print(f"Alert detection error: {e}")

        return {
            'pcap': pcap_file,
            'analysis': analyzer_out,
            'timing': correlator_out if os.path.exists(correlator_out) else None,
            'fingerprint': fingerprint_out if os.path.exists(fingerprint_out) else None,
            'gnn': gnn_out,
            'has_tor_flows': True
        }
    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")
        return None


def aggregate_results(results_list):
    csv_path = os.path.join(RESULTS_DIR, 'batch_summary.csv')
    with open(csv_path, mode='w', newline='') as csvfile:
        fieldnames = ['PCAP', 'Rank', 'Relay Nickname', 'IP Address', 'Confidence', 'Method']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for res in results_list:
            if not res or not res.get('has_tor_flows') or not res.get('gnn'):
                continue
            try:
                with open(res['gnn'], 'r') as f:
                    gnn_data = json.load(f)
                top_guards = gnn_data.get('predictions', [])[:3]
                if not top_guards:
                    continue
                for idx, guard in enumerate(top_guards, 1):
                    writer.writerow({
                        'PCAP': os.path.basename(res['pcap']),
                        'Rank': idx,
                        'Relay Nickname': guard.get('nickname', 'Unknown'),
                        'IP Address': guard.get('relay_ip', 'Unknown'),
                        'Confidence': guard.get('confidence', 0),
                        'Method': guard.get('analysis_method', 'GNN')
                    })
            except Exception as e:
                print(f"Failed to load GNN results for {res['pcap']}: {e}")
    print(f"\nBatch summary saved to {csv_path}")


def main():
    pcaps = [os.path.join(PCAP_DIR, f) for f in os.listdir(PCAP_DIR) if f.endswith('.pcap')]
    print(f"Found {len(pcaps)} PCAP files to analyze.")

    all_results = []
    successful_count = 0
    zero_flow_count = 0
    failed_count = 0
    analysis_times = []

    start_batch = time.time()

    for pcap in pcaps:
        start = time.time()
        result = analyze_pcap(pcap)
        duration = time.time() - start

        if result:
            all_results.append(result)
            analysis_times.append({
                "pcap": os.path.basename(pcap),
                "duration_sec": round(duration, 2),
                "success": bool(result.get('has_tor_flows'))
            })
            if result.get('has_tor_flows'):
                successful_count += 1
            else:
                zero_flow_count += 1
        else:
            failed_count += 1
            analysis_times.append({
                "pcap": os.path.basename(pcap),
                "duration_sec": round(duration, 2),
                "success": False
            })

    total_time = time.time() - start_batch

    print(f"\n{'='*70}")
    print(f"Batch Analysis Complete")
    print(f"{'='*70}")
    print(f"Total PCAPs processed: {len(pcaps)}")
    print(f"Successfully analyzed (with Tor flows): {successful_count}")
    print(f"PCAPs with no Tor flows: {zero_flow_count}")
    print(f"Failed PCAPs: {failed_count}")
    print(f"Total batch time: {round(total_time, 2)} seconds")
    print(f"{'='*70}")

    if all_results:
        aggregate_results(all_results)

    # Save performance metrics as JSON
    with open(PERF_METRICS, 'w') as f:
        json.dump({
            "per_file": analysis_times,
            "batch_total_sec": round(total_time, 2),
            "total_pcaps": len(pcaps),
            "successful": successful_count,
            "no_tor_flows": zero_flow_count,
            "failed": failed_count
        }, f, indent=2)
    print(f"\nPerformance metrics saved to {PERF_METRICS}")


if __name__ == '__main__':
    main()
