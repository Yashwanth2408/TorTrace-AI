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
    
    def __init__(self, db_path='../data/tor_relays.db'):
        """
        Initialize analyzer with relay database.
        
        Args:
            db_path: Path to Tor relay database
        """
        self.db_path = db_path
        self.tor_relays = self.load_tor_relays()
        logger.info(f"Loaded {len(self.tor_relays)} Tor relays from database")
    
    def load_tor_relays(self):
        """
        Load known Tor relay IPs from database.
        
        Returns:
            dict: Mapping of IP addresses to relay information
        """
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
        """
        Analyze PCAP file for Tor traffic.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            dict: Analysis results including flows and statistics
        """
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
                
                # Identify Tor relay communication
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
                
                tor_flows[flow_id]['end_time'] = timestamp
                tor_flows[flow_id]['total_bytes'] += packet_size
                tor_flows[flow_id]['packet_count'] += 1
        
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
    
    def _print_summary(self, results, tor_flows):
        """Print analysis summary."""
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
        """
        Extract timing patterns for correlation analysis.
        
        Args:
            flow: Flow dictionary containing packet information
            
        Returns:
            dict: Timing pattern features
        """
        if not flow['packets']:
            return None
        
        packets = flow['packets']
        
        # Calculate inter-packet arrival times
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
        """
        Save analysis results to JSON file.
        
        Args:
            results: Analysis results dictionary
            output_file: Output JSON file path
            
        Returns:
            dict: Output data written to file
        """
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
        return output_data


def main():
    """Main execution routine."""
    print("=" * 70)
    print("TorTrace-AI: PCAP Traffic Analyzer")
    print("=" * 70)
    
    analyzer = TorTrafficAnalyzer()
    
    pcap_file = "../data/pcap_files/sample.pcap"
    
    print(f"\nNote: Place PCAP files in ../data/pcap_files/")
    print(f"Looking for: {pcap_file}")
    
    if os.path.exists(pcap_file):
        results = analyzer.analyze_pcap(pcap_file)
        
        if results and results['tor_flows'] > 0:
            output_file = "../data/pcap_files/analysis_results.json"
            analyzer.save_analysis(results, output_file)
    else:
        print("\nNo sample PCAP file found")
        print("Create with: sudo tcpdump -i any -w sample.pcap port 9001")


if __name__ == "__main__":
    main()
