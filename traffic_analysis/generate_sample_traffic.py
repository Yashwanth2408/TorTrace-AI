#!/usr/bin/env python3
"""
Generate realistic sample Tor traffic patterns for testing
"""

import sqlite3
import random
from scapy.all import IP, TCP, Raw, wrpcap
import time

def generate_realistic_pcap():
    """Generate realistic PCAP with correlated Tor traffic"""
    print("🔧 Generating realistic Tor traffic with timing patterns...")
    
    # Load Tor relays from database
    conn = sqlite3.connect('../data/tor_relays.db')
    cursor = conn.cursor()
    
    # Get some guard nodes and exit nodes
    cursor.execute('SELECT address, nickname FROM relays WHERE is_guard = 1 LIMIT 3')
    guard_nodes = cursor.fetchall()
    
    cursor.execute('SELECT address, nickname FROM relays WHERE is_exit = 1 LIMIT 3')
    exit_nodes = cursor.fetchall()
    
    conn.close()
    
    if not guard_nodes or not exit_nodes:
        print("❌ Need both guard and exit nodes in database")
        return
    
    print(f"✅ Using {len(guard_nodes)} guard nodes, {len(exit_nodes)} exit nodes")
    
    packets = []
    src_ip = "192.168.1.100"  # Simulated client
    base_time = time.time()
    
    # Simulate 3 different Tor circuits
    for circuit_id in range(3):
        guard_ip, guard_name = random.choice(guard_nodes)
        exit_ip, exit_name = random.choice(exit_nodes)
        
        print(f"   Circuit {circuit_id+1}: {src_ip} -> {guard_name} -> ... -> {exit_name}")
        
        # Generate correlated timing pattern
        base_ipt = 0.01 + random.random() * 0.02  # Base inter-packet time
        noise = 0.003  # Timing noise
        
        # Entry traffic (client -> guard node)
        entry_times = []
        for i in range(30):
            timestamp = base_time + circuit_id * 2.0 + i * base_ipt + random.uniform(-noise, noise)
            entry_times.append(timestamp)
            
            size = random.randint(200, 1400)
            pkt = IP(src=src_ip, dst=guard_ip)/TCP(sport=50000+circuit_id, dport=9001)/Raw(b"X"*size)
            pkt.time = timestamp
            packets.append(pkt)
        
        # Exit traffic (exit node -> destination) - CORRELATED timing
        # Add realistic network delay
        network_delay = 0.15 + random.random() * 0.1
        
        for i, entry_time in enumerate(entry_times):
            # Exit packet arrives after network delay with similar timing pattern
            timestamp = entry_time + network_delay + random.uniform(-noise*2, noise*2)
            
            size = random.randint(200, 1400)
            # Simulate exit to destination (reversed perspective)
            pkt = IP(src=exit_ip, dst="8.8.8.8")/TCP(sport=9001, dport=443)/Raw(b"Y"*size)
            pkt.time = timestamp
            packets.append(pkt)
        
        # Response traffic (destination -> exit node)
        for i in range(25):
            timestamp = base_time + circuit_id * 2.0 + i * base_ipt * 1.2 + 0.3
            size = random.randint(100, 800)
            pkt = IP(src="8.8.8.8", dst=exit_ip)/TCP(sport=443, dport=9001)/Raw(b"Z"*size)
            pkt.time = timestamp
            packets.append(pkt)
        
        # Response back to client (guard -> client) - also correlated
        for i in range(25):
            timestamp = base_time + circuit_id * 2.0 + i * base_ipt * 1.2 + 0.45
            size = random.randint(100, 800)
            pkt = IP(src=guard_ip, dst=src_ip)/TCP(sport=9001, dport=50000+circuit_id)/Raw(b"W"*size)
            pkt.time = timestamp
            packets.append(pkt)
    
    # Sort packets by time
    packets.sort(key=lambda x: x.time)
    
    # Save PCAP
    output_file = '../data/pcap_files/sample.pcap'
    wrpcap(output_file, packets)
    
    print(f"✅ Generated {len(packets)} packets in {len(packets)//4} flows")
    print(f"📁 Saved to: {output_file}")

if __name__ == "__main__":
    generate_realistic_pcap()
