#!/usr/bin/env python3
"""
TorTrace-AI: Timing Correlation Engine

Correlates traffic timing patterns to identify probable entry (guard) nodes.
Uses statistical correlation analysis to match entry and exit traffic patterns.
"""

import json
import numpy as np
from scipy import stats
from datetime import datetime
import sqlite3
import logging
import argparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TimingCorrelator:
    """
    Traffic timing correlation analyzer.

    Performs statistical correlation analysis on traffic timing patterns
    to identify probable guard node entry points based on temporal
    similarities between entry and exit traffic.
    """
    
    def __init__(self, db_path='../data/tor_relays.db'):
        """
        Initialize timing correlator.

        Args:
            db_path: Path to Tor relay database
        """
        self.db_path = db_path
        logger.info("Timing Correlator initialized")
    
    def load_traffic_patterns(self, json_file):
        """
        Load analyzed traffic patterns from JSON file.

        Args:
            json_file: Path to traffic analysis JSON file

        Returns:
            list: Traffic pattern dictionaries
        """
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        patterns = data['timing_patterns']
        logger.info(f"Loaded {len(patterns)} traffic patterns")
        return patterns
    
    def correlate_timing(self, pattern1, pattern2):
        """
        Correlate two timing patterns using Pearson correlation.

        Args:
            pattern1: First traffic pattern
            pattern2: Second traffic pattern

        Returns:
            tuple: (correlation_coefficient, p_value)
        """
        ipt1 = pattern1.get('inter_packet_times', [])
        ipt2 = pattern2.get('inter_packet_times', [])
        
        if len(ipt1) < 3 or len(ipt2) < 3:
            return 0.0, 1.0
        
        # Normalize sequence lengths
        min_len = min(len(ipt1), len(ipt2))
        ipt1 = ipt1[:min_len]
        ipt2 = ipt2[:min_len]
        
        try:
            correlation, p_value = stats.pearsonr(ipt1, ipt2)
            return correlation, p_value
        except:
            return 0.0, 1.0
    
    def find_guard_node_candidates(self, patterns, correlation_threshold=0.6):
        """
        Identify probable guard nodes through timing correlation.

        Args:
            patterns: List of traffic patterns
            correlation_threshold: Minimum correlation coefficient

        Returns:
            dict: Guard node candidates with confidence scores
        """
        logger.info(f"Analyzing {len(patterns)} traffic patterns")
        
        guard_candidates = {}
        correlations_found = 0
        
        # Separate patterns by relay type
        entry_patterns = [p for p in patterns if not p.get('is_exit', False)]
        exit_patterns = [p for p in patterns if p.get('is_exit', False)]
        
        logger.info(f"Entry patterns: {len(entry_patterns)}, Exit patterns: {len(exit_patterns)}")
        
        if not exit_patterns:
            exit_patterns = patterns
            entry_patterns = patterns
        
        # Correlate entry with exit patterns
        for entry in entry_patterns:
            best_correlation = 0
            best_match = None
            
            for exit_p in exit_patterns:
                if entry['flow_id'] == exit_p['flow_id']:
                    continue
                
                corr, p_val = self.correlate_timing(entry, exit_p)
                
                if corr > best_correlation and p_val < 0.05:
                    best_correlation = corr
                    best_match = exit_p
            
            if best_correlation > correlation_threshold and best_match:
                guard_relay = entry.get('tor_relay', 'unknown')
                
                if guard_relay not in guard_candidates:
                    guard_candidates[guard_relay] = {
                        'relay_ip': guard_relay,
                        'nickname': entry.get('relay_nickname', 'unknown'),
                        'matches': [],
                        'avg_correlation': 0,
                        'confidence': 0
                    }
                
                guard_candidates[guard_relay]['matches'].append({
                    'correlation': best_correlation,
                    'exit_relay': best_match.get('tor_relay', 'unknown'),
                    'flow': entry['flow_id']
                })
                correlations_found += 1
        
        # Calculate confidence scores
        for relay_ip, candidate in guard_candidates.items():
            if candidate['matches']:
                avg_corr = np.mean([m['correlation'] for m in candidate['matches']])
                candidate['avg_correlation'] = float(avg_corr)
                # Confidence based on correlation strength and number of matches
                candidate['confidence'] = min(100, int(avg_corr * 100 + len(candidate['matches']) * 5))
        
        sorted_candidates = sorted(
            guard_candidates.items(),
            key=lambda x: x[1]['confidence'],
            reverse=True
        )
        
        logger.info(f"Found {len(guard_candidates)} guard node candidates")
        logger.info(f"Total correlations: {correlations_found}")
        
        return dict(sorted_candidates)
    
    def generate_attribution_report(self, guard_candidates, output_file):
        """
        Generate detailed attribution report.

        Args:
            guard_candidates: Dictionary of guard node candidates
            output_file: Output JSON file path

        Returns:
            dict: Report data
        """
        report = {
            'analysis_time': datetime.now().isoformat(),
            'analysis_method': 'Statistical Timing Correlation',
            'total_candidates': len(guard_candidates),
            'guard_nodes': []
        }
        
        for relay_ip, data in guard_candidates.items():
            report['guard_nodes'].append({
                'relay_ip': relay_ip,
                'nickname': data['nickname'],
                'confidence': data['confidence'],
                'avg_correlation': data['avg_correlation'],
                'num_matches': len(data['matches']),
                'matches': data['matches'][:5]
            })
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Attribution report saved: {output_file}")
        return report
    
    def display_results(self, guard_candidates):
        """
        Display correlation analysis results.

        Args:
            guard_candidates: Dictionary of guard node candidates
        """
        if not guard_candidates:
            print("\nNo guard node candidates found")
            return
        
        print("\n" + "=" * 70)
        print("Probable Guard Node Attribution")
        print("=" * 70)
        
        for i, (relay_ip, data) in enumerate(list(guard_candidates.items())[:10], 1):
            confidence = data['confidence']
            conf_bar = "█" * (confidence // 10) + "░" * (10 - confidence // 10)
            
            print(f"\n{i}. {data['nickname'][:25]:25s} ({relay_ip})")
            print(f"   Confidence: [{conf_bar}] {confidence}%")
            print(f"   Correlation: {data['avg_correlation']:.3f}")
            print(f"   Matches: {len(data['matches'])}")
            
            if data['matches']:
                print(f"   Top match: {data['matches'][0]['exit_relay']} "
                      f"(correlation: {data['matches'][0]['correlation']:.3f})")

def main():
    """Main execution routine."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='Input JSON file with traffic patterns')
    parser.add_argument('--output', required=True, help='Output JSON file for attribution report')
    parser.add_argument('--db', default='../data/tor_relays.db', help='Path to Tor relay database')
    args = parser.parse_args()

    print("=" * 70)
    print("TorTrace-AI: Timing Correlation Engine")
    print("=" * 70)

    correlator = TimingCorrelator(db_path=args.db)

    patterns = correlator.load_traffic_patterns(args.input)
    guard_candidates = correlator.find_guard_node_candidates(patterns)
    correlator.display_results(guard_candidates)

    if guard_candidates:
        correlator.generate_attribution_report(guard_candidates, args.output)

        print("\n" + "=" * 70)
        print("Correlation analysis complete")
        print("=" * 70)

if __name__ == "__main__":
    main()
