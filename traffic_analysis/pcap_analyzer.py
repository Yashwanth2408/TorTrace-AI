#!/usr/bin/env python3
"""
TorTrace-AI: PCAP Traffic Analyzer

Identifies and analyzes Tor traffic patterns from packet capture files.
Correlates packets with known Tor relay database and extracts timing patterns.
"""

from scapy.all import rdpcap, TCP, IP, wrpcap
from scapy.packet import Raw
import sqlite3
from datetime import datetime
import json
import os
import logging
import argparse
import math
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TorTrafficAnalyzer:
    """
    PCAP traffic analyzer for Tor network connections.
    Identifies Tor traffic by correlating packet source/destination
    addresses with known Tor relay database. Extracts timing patterns
    and flow characteristics for downstream correlation analysis.
    """

    def __init__(self, db_path='data/tor_relays.db'):
        self.db_path = db_path
        self.tor_relays = self.load_tor_relays()
        logger.info(f"Loaded {len(self.tor_relays)} Tor relays from database")

    def load_tor_relays(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT address, fingerprint, nickname, is_guard, is_exit FROM relays')
        relays = {}
        for row in cursor.fetchall():
            relays[row[0]] = {
                'fingerprint': row[1],
                'nickname': row[2],
                'is_guard': bool(row[3]),
                'is_exit': bool(row[4])
            }
        conn.close()
        return relays

    def analyze_pcap(self, pcap_file):
        logger.info(f"Analyzing PCAP file: {pcap_file}")
        if not os.path.exists(pcap_file):
            logger.error(f"File not found: {pcap_file}")
            return None
        try:
            packets = rdpcap(pcap_file)
            logger.info(f"Loaded {len(packets)} packets")
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            return None
        tor_flows = {}
        non_tor_packets = 0

        for pkt in packets:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                timestamp = float(pkt.time)
                packet_size = len(pkt)
                tor_ip = None
                direction = None
                if dst_ip in self.tor_relays:
                    tor_ip = dst_ip
                    direction = 'outgoing'
                elif src_ip in self.tor_relays:
                    tor_ip = src_ip
                    direction = 'incoming'
                else:
                    non_tor_packets += 1
                    continue
                flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                if flow_id not in tor_flows:
                    tor_flows[flow_id] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'tor_relay': self.tor_relays[tor_ip],
                        'tor_relay_ip': tor_ip,
                        'direction': direction,
                        'packets': [],
                        'packet_sizes': [],
                        'start_time': timestamp,
                        'end_time': timestamp,
                        'total_bytes': 0,
                        'packet_count': 0
                    }
                tor_flows[flow_id]['packets'].append({
                    'timestamp': timestamp,
                    'size': packet_size,
                    'direction': 1 if direction == 'outgoing' else -1
                })
                tor_flows[flow_id]['packet_sizes'].append(packet_size)
                tor_flows[flow_id]['end_time'] = timestamp
                tor_flows[flow_id]['total_bytes'] += packet_size
                tor_flows[flow_id]['packet_count'] += 1

        for flow_id, flow in tor_flows.items():
            packets_in_flow = flow['packets']
            bursts = self._detect_bursts(packets_in_flow)
            flow['burst_count'] = len(bursts)
            flow['avg_burst_duration'] = sum(b['duration'] for b in bursts) / len(bursts) if bursts else 0
            flow['max_burst_len'] = max(b['length'] for b in bursts) if bursts else 0
            out_pkts = [p for p in packets_in_flow if p['direction'] == 1]
            in_pkts = [p for p in packets_in_flow if p['direction'] == -1]
            flow['outgoing_packet_count'] = len(out_pkts)
            flow['incoming_packet_count'] = len(in_pkts)
            flow['outgoing_bytes'] = sum(p['size'] for p in out_pkts)
            flow['incoming_bytes'] = sum(p['size'] for p in in_pkts)
            entropies = []
            for pkt in packets:
                if IP in pkt and TCP in pkt:
                    raw_payload = self._get_raw_payload(pkt)
                    if raw_payload:
                        entropies.append(self._shannon_entropy(raw_payload))
            flow['avg_payload_entropy'] = sum(entropies) / len(entropies) if entropies else 0
            syn_count = 0
            ack_count = 0
            fin_count = 0
            rst_count = 0
            for pkt in packets:
                if IP in pkt and TCP in pkt:
                    if self._has_flag(pkt, 'S'):
                        syn_count += 1
                    if self._has_flag(pkt, 'A'):
                        ack_count += 1
                    if self._has_flag(pkt, 'F'):
                        fin_count += 1
                    if self._has_flag(pkt, 'R'):
                        rst_count += 1
            flow['syn_count'] = syn_count
            flow['ack_count'] = ack_count
            flow['fin_count'] = fin_count
            flow['rst_count'] = rst_count

            # PACKET SIZE ENTROPY FEATURE (NEW)
            flow['packet_size_entropy'] = self._packet_size_entropy(flow['packet_sizes'])

        results = {
            'pcap_file': pcap_file,
            'total_packets': len(packets),
            'tor_flows': len(tor_flows),
            'non_tor_packets': non_tor_packets,
            'flows': list(tor_flows.values())
        }

        logger.info(f"Analysis complete: {len(tor_flows)} Tor flows detected")
        self._print_summary(results, tor_flows)
        return results

    def _packet_size_entropy(self, packet_sizes):
        if len(packet_sizes) == 0:
            return 0.0
        _, counts = np.unique(packet_sizes, return_counts=True)
        probabilities = counts / len(packet_sizes)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)

    def _detect_bursts(self, packets, threshold_ms=50):
        bursts = []
        if not packets:
            return bursts
        burst_start = packets[0]['timestamp']
        last_pkt_time = burst_start
        burst_len = 1
        for pkt in packets[1:]:
            if (pkt['timestamp'] - last_pkt_time) * 1000 <= threshold_ms:
                burst_len += 1
            else:
                bursts.append({'start': burst_start, 'end': last_pkt_time, 'duration': last_pkt_time - burst_start, 'length': burst_len})
                burst_start = pkt['timestamp']
                burst_len = 1
            last_pkt_time = pkt['timestamp']
        bursts.append({'start': burst_start, 'end': last_pkt_time, 'duration': last_pkt_time - burst_start, 'length': burst_len})
        return bursts

    def _get_raw_payload(self, pkt):
        try:
            if Raw in pkt:
                return bytes(pkt[Raw].load)
        except Exception:
            return None
        return None

    def _shannon_entropy(self, data):
        if not data:
            return 0
        from collections import Counter
        counts = Counter(data)
        entropy = 0
        length = len(data)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _has_flag(self, pkt, flag_char):
        try:
            if TCP in pkt:
                flags = pkt[TCP].flags
                return flag_char.encode() in bytes(flags)
        except Exception:
            return False
        return False

    def _print_summary(self, results, tor_flows):
        print("\nAnalysis Results:")
        print(f"  Total packets: {results['total_packets']}")
        print(f"  Tor flows detected: {results['tor_flows']}")
        print(f"  Non-Tor packets: {results['non_tor_packets']}")
        if tor_flows:
            print("\nDetected Tor Connections (showing first 10):")
            for i, (flow_id, flow) in enumerate(list(tor_flows.items())[:10], 1):
                relay_info = flow['tor_relay']
                print(f"  {i}. {flow['src_ip']:15s} -> {flow['tor_relay_ip']:15s}")
                print(f"     Relay: {relay_info['nickname'][:20]:20s} | "
                      f"Guard: {relay_info['is_guard']} | Exit: {relay_info['is_exit']}")
                print(f"     Packets: {flow['packet_count']}, Bytes: {flow['total_bytes']}, "
                      f"Duration: {flow['end_time'] - flow['start_time']:.3f}s")

    def extract_timing_patterns(self, flow):
        if not flow['packets']:
            return None
        packets = flow['packets']
        ipt_times = []
        for i in range(1, len(packets)):
            ipt = packets[i]['timestamp'] - packets[i-1]['timestamp']
            ipt_times.append(ipt)
        sizes = [p['size'] for p in packets]
        directions = [p['direction'] for p in packets]
        pattern = {
            'flow_id': f"{flow['src_ip']}->{flow['dst_ip']}",
            'packet_count': len(packets),
            'duration': flow['end_time'] - flow['start_time'],
            'total_bytes': flow['total_bytes'],
            'avg_packet_size': sum(sizes) / len(sizes) if sizes else 0,
            'inter_packet_times': ipt_times[:100],
            'packet_sizes': sizes[:100],
            'directions': directions[:100],
            'tor_relay': flow['tor_relay_ip'],
            'relay_nickname': flow['tor_relay']['nickname'],
            'is_guard': flow['tor_relay']['is_guard'],
            'is_exit': flow['tor_relay']['is_exit']
        }
        return pattern

    def save_analysis(self, results, output_file):
        patterns = []
        for flow in results['flows']:
            pattern = self.extract_timing_patterns(flow)
            if pattern:
                patterns.append(pattern)
        output_data = {
            'pcap_file': results['pcap_file'],
            'analysis_time': datetime.now().isoformat(),
            'total_packets': results['total_packets'],
            'tor_flows': results['tor_flows'],
            'timing_patterns': patterns
        }
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        logger.info(f"Analysis saved to: {output_file}")
        print(f"\nResults saved to {output_file}")
        return output_data
    
    def save_features_to_csv(self, results, output_csv):
        """
        Save feature matrix (including packet_size_entropy) for all flows to CSV.
        """
        import csv
        flows = results['flows']
        if not flows:
            print(f"No flows to write in {output_csv}")
            return

        # List ALL your desired feature keys here, matching your ML pipeline order
        feature_keys = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'direction',
            'packet_count', 'total_bytes', 'start_time', 'end_time',
            'burst_count', 'avg_burst_duration', 'max_burst_len',
            'outgoing_packet_count', 'incoming_packet_count',
            'outgoing_bytes', 'incoming_bytes',
            'avg_payload_entropy', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
            'packet_size_entropy'
        ]

        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=feature_keys)
            writer.writeheader()
            for flow in flows:
                row = {k: flow.get(k, 0) for k in feature_keys}
                writer.writerow(row)
        print(f"Features saved to {output_csv}")


def main():
    """Main execution routine."""
    print("=" * 70)
    print("TorTrace-AI: PCAP Traffic Analyzer")
    print("=" * 70)

    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', required=True, help='Input PCAP file path')
    parser.add_argument('--out', required=True, help='Output JSON analysis file path')
    parser.add_argument('--db', default='data/tor_relays.db', help='Path to Tor relay database')
    args = parser.parse_args()

    analyzer = TorTrafficAnalyzer(db_path=args.db)

    if os.path.exists(args.pcap):
        results = analyzer.analyze_pcap(args.pcap)
        if results:
            # CRITICAL FIX: Always save results, even if 0 Tor flows
            analyzer.save_analysis(results, args.out)
            analyzer.save_features_to_csv(results, args.out.replace('.json', '.csv'))
        else:
            print(f"Error: Could not analyze PCAP file {args.pcap}")
    else:
        print(f"Error: No PCAP file found at {args.pcap}")

if __name__ == "__main__":
    main()
