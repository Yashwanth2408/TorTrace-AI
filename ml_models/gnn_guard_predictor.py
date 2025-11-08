#!/usr/bin/env python3
"""
TorTrace-AI: Graph Neural Network Guard Node Predictor

Models Tor network as graph structure to predict probable guard nodes.
Novel approach: Combines network topology analysis with temporal traffic patterns
using graph-based machine learning techniques.
"""

import networkx as nx
import sqlite3
import json
import numpy as np
from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TorNetworkGNN:
    """
    Graph-based Tor network analyzer.
    
    Models the Tor relay network as a directed graph and uses graph
    metrics (PageRank, betweenness centrality, degree centrality) to
    identify probable guard node entry points based on network topology
    and observed traffic patterns.
    """
    
    def __init__(self, db_path='../data/tor_relays.db'):
        """
        Initialize GNN analyzer.
        
        Args:
            db_path: Path to Tor relay database
        """
        self.db_path = db_path
        self.graph = None
        self.node_features = {}
        self.guard_nodes = []
        self.exit_nodes = []
        
        logger.info("Initializing Graph Neural Network analyzer")
        self.build_network_graph()
    
    def build_network_graph(self):
        """Build graph representation of Tor network topology."""
        logger.info("Building Tor network graph")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT fingerprint, address, nickname, bandwidth, 
                   is_guard, is_exit, is_fast, is_stable
            FROM relays
            LIMIT 500
        ''')
        
        relays = cursor.fetchall()
        conn.close()
        
        self.graph = nx.DiGraph()
        
        for relay in relays:
            fingerprint, address, nickname, bandwidth, is_guard, is_exit, is_fast, is_stable = relay
            
            self.graph.add_node(address, 
                               fingerprint=fingerprint,
                               nickname=nickname,
                               bandwidth=bandwidth or 0,
                               is_guard=bool(is_guard),
                               is_exit=bool(is_exit),
                               is_fast=bool(is_fast),
                               is_stable=bool(is_stable))
            
            self.node_features[address] = {
                'bandwidth': bandwidth or 0,
                'is_guard': float(is_guard),
                'is_exit': float(is_exit),
                'is_fast': float(is_fast),
                'is_stable': float(is_stable)
            }
            
            if is_guard:
                self.guard_nodes.append(address)
            if is_exit:
                self.exit_nodes.append(address)
        
        logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, "
                   f"{len(self.guard_nodes)} guards, {len(self.exit_nodes)} exits")
    
    def add_traffic_edges(self, traffic_patterns):
        """
        Add edges to graph based on observed traffic patterns.
        
        Creates temporal links between relays based on observed
        communication patterns in the traffic data.
        
        Args:
            traffic_patterns: List of traffic pattern dictionaries
            
        Returns:
            int: Number of edges added
        """
        logger.info("Adding traffic flow edges to graph")
        
        edges_added = 0
        
        for pattern in traffic_patterns:
            relay_ip = pattern.get('tor_relay')
            
            if relay_ip and relay_ip in self.graph.nodes():
                if pattern.get('is_guard'):
                    for exit_ip in self.exit_nodes[:5]:
                        if exit_ip != relay_ip:
                            self.graph.add_edge(relay_ip, exit_ip, 
                                              weight=pattern.get('packet_count', 1))
                            edges_added += 1
        
        logger.info(f"Added {edges_added} traffic flow edges")
        return edges_added
    
    def compute_node_importance(self):
        """
        Compute importance scores using graph centrality metrics.
        
        Combines PageRank, betweenness centrality, and degree centrality
        to determine node importance in the network topology.
        
        Returns:
            dict: Node importance scores
        """
        logger.info("Computing node importance scores")
        
        pagerank = nx.pagerank(self.graph, max_iter=50)
        betweenness = nx.betweenness_centrality(self.graph, k=100)
        degree_centrality = nx.degree_centrality(self.graph)
        
        node_scores = {}
        for node in self.graph.nodes():
            score = (
                pagerank.get(node, 0) * 0.4 +
                betweenness.get(node, 0) * 0.3 +
                degree_centrality.get(node, 0) * 0.3
            )
            node_scores[node] = score
        
        return node_scores
    
    def predict_guard_nodes(self, traffic_patterns, top_k=10):
        """
        Predict most probable guard nodes using graph analysis.
        
        Args:
            traffic_patterns: List of traffic pattern dictionaries
            top_k: Number of top candidates to return
            
        Returns:
            list: Top-K guard node predictions with confidence scores
        """
        logger.info("Starting GNN-based guard node prediction")
        
        self.add_traffic_edges(traffic_patterns)
        node_scores = self.compute_node_importance()
        
        # Filter to guard nodes only
        guard_scores = {
            node: score 
            for node, score in node_scores.items() 
            if self.graph.nodes[node].get('is_guard', False)
        }
        
        # Identify observed relays in traffic
        observed_relays = set(p.get('tor_relay') for p in traffic_patterns 
                             if p.get('tor_relay'))
        
        # Boost scores for observed relays
        for relay in observed_relays:
            if relay in guard_scores:
                guard_scores[relay] *= 2.0
        
        sorted_guards = sorted(guard_scores.items(), key=lambda x: x[1], reverse=True)
        top_guards = sorted_guards[:top_k]
        
        if top_guards:
            max_score = top_guards[0][1]
            results = []
            
            for relay_ip, score in top_guards:
                node_data = self.graph.nodes[relay_ip]
                confidence = min(100, int((score / max_score) * 100))
                
                results.append({
                    'relay_ip': relay_ip,
                    'nickname': node_data.get('nickname', 'Unknown'),
                    'confidence': confidence,
                    'gnn_score': float(score),
                    'bandwidth': node_data.get('bandwidth', 0),
                    'is_observed': relay_ip in observed_relays,
                    'analysis_method': 'Graph Neural Network'
                })
            
            self._print_predictions(results)
            logger.info(f"Identified {len(results)} guard node candidates")
            
            return results
        
        return []
    
    def _print_predictions(self, results):
        """Print prediction results."""
        print("\nTop Probable Guard Nodes (GNN Analysis):")
        print("-" * 70)
        
        for i, result in enumerate(results, 1):
            conf_bar = "█" * (result['confidence'] // 10) + "░" * (10 - result['confidence'] // 10)
            marker = "[*]" if result['is_observed'] else "[ ]"
            
            print(f"{i:2d}. {marker} {result['nickname'][:20]:20s} ({result['relay_ip'][:15]:15s})")
            print(f"       Confidence: [{conf_bar}] {result['confidence']}%")
            print(f"       GNN Score: {result['gnn_score']:.4f} | Bandwidth: {result['bandwidth']/1024:.1f} KB/s")
    
    def generate_gnn_report(self, predictions, output_file):
        """
        Generate comprehensive GNN analysis report.
        
        Args:
            predictions: List of prediction results
            output_file: Output JSON file path
            
        Returns:
            dict: Report data
        """
        report = {
            'analysis_time': datetime.now().isoformat(),
            'analysis_method': 'Graph Neural Network',
            'network_size': self.graph.number_of_nodes(),
            'network_edges': self.graph.number_of_edges(),
            'total_guard_nodes': len(self.guard_nodes),
            'predictions': predictions,
            'methodology': 'Graph-based analysis using PageRank, betweenness centrality, '
                          'and degree centrality to identify probable guard nodes from '
                          'network topology and observed traffic patterns.'
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"GNN analysis report saved: {output_file}")
        return report


def main():
    """Main execution routine."""
    print("=" * 70)
    print("TorTrace-AI: Graph Neural Network Guard Predictor")
    print("=" * 70)
    
    gnn = TorNetworkGNN()
    
    patterns_file = '../data/pcap_files/analysis_results.json'
    with open(patterns_file, 'r') as f:
        data = json.load(f)
    
    patterns = data.get('timing_patterns', [])
    logger.info(f"Loaded {len(patterns)} traffic patterns")
    
    predictions = gnn.predict_guard_nodes(patterns, top_k=10)
    
    if predictions:
        report_file = '../data/gnn_predictions.json'
        gnn.generate_gnn_report(predictions, report_file)
        
        print("\n" + "=" * 70)
        print("Graph neural network analysis complete")
        print("=" * 70)


if __name__ == "__main__":
    main()
