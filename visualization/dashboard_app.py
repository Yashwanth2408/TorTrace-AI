#!/usr/bin/env python3
"""
TorTrace-AI: Web Dashboard

RESTful API and visualization interface for Tor attribution analysis.
Provides real-time access to network statistics and attribution results.
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import sqlite3
import os
from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)


class DashboardData:
    """
    Data provider for dashboard API endpoints.
    
    Aggregates data from database and analysis result files
    to provide unified interface for visualization.
    """
    
    def __init__(self):
        """Initialize dashboard data provider."""
        self.db_path = '../data/tor_relays.db'
    
    def get_network_stats(self):
        """
        Get Tor network statistics.
        
        Returns:
            dict: Network statistics including relay counts and bandwidth
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM relays')
        total = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM relays WHERE is_guard = 1')
        guards = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM relays WHERE is_exit = 1')
        exits = cursor.fetchone()[0]
        
        cursor.execute('SELECT SUM(bandwidth) FROM relays')
        bandwidth = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_relays': total,
            'guard_nodes': guards,
            'exit_nodes': exits,
            'total_bandwidth_mbps': round(bandwidth / 1024 / 1024, 2)
        }
    
    def get_attribution_results(self):
        """
        Get all attribution analysis results.
        
        Returns:
            dict: Combined results from all analysis methods
        """
        results = {
            'timing_correlation': {},
            'gnn_predictions': {},
            'website_fingerprinting': {}
        }
        
        if os.path.exists('../data/attribution_report.json'):
            with open('../data/attribution_report.json', 'r') as f:
                results['timing_correlation'] = json.load(f)
        
        if os.path.exists('../data/gnn_predictions.json'):
            with open('../data/gnn_predictions.json', 'r') as f:
                results['gnn_predictions'] = json.load(f)
        
        if os.path.exists('../data/website_fingerprint_report.json'):
            with open('../data/website_fingerprint_report.json', 'r') as f:
                results['website_fingerprinting'] = json.load(f)
        
        return results
    
    def get_top_guard_candidates(self, limit=5):
        """
        Get top guard node candidates from all analysis methods.
        
        Args:
            limit: Maximum number of candidates per method
            
        Returns:
            list: Top guard node candidates with confidence scores
        """
        candidates = []
        
        if os.path.exists('../data/gnn_predictions.json'):
            with open('../data/gnn_predictions.json', 'r') as f:
                gnn_data = json.load(f)
                for pred in gnn_data.get('predictions', [])[:limit]:
                    candidates.append({
                        'method': 'GNN',
                        'relay_ip': pred['relay_ip'],
                        'nickname': pred['nickname'],
                        'confidence': pred['confidence']
                    })
        
        if os.path.exists('../data/attribution_report.json'):
            with open('../data/attribution_report.json', 'r') as f:
                timing_data = json.load(f)
                for guard in timing_data.get('guard_nodes', [])[:limit]:
                    candidates.append({
                        'method': 'Timing',
                        'relay_ip': guard['relay_ip'],
                        'nickname': guard['nickname'],
                        'confidence': guard['confidence']
                    })
        
        return candidates


dashboard = DashboardData()


@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/stats')
def api_stats():
    """
    API endpoint: Network statistics.
    
    Returns:
        JSON response with network statistics
    """
    try:
        return jsonify(dashboard.get_network_stats())
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/attribution')
def api_attribution():
    """
    API endpoint: Attribution analysis results.
    
    Returns:
        JSON response with all attribution results
    """
    try:
        return jsonify(dashboard.get_attribution_results())
    except Exception as e:
        logger.error(f"Error fetching attribution results: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/top_guards')
def api_top_guards():
    """
    API endpoint: Top guard node candidates.
    
    Returns:
        JSON response with top guard candidates
    """
    try:
        return jsonify(dashboard.get_top_guard_candidates())
    except Exception as e:
        logger.error(f"Error fetching top guards: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network_graph')
def api_network_graph():
    """
    API endpoint: Network graph data.
    
    Returns:
        JSON response with nodes and edges for visualization
    """
    try:
        conn = sqlite3.connect(dashboard.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT address, nickname, is_guard, is_exit, bandwidth
            FROM relays
            LIMIT 50
        ''')
        
        nodes = []
        for row in cursor.fetchall():
            nodes.append({
                'id': row[0],
                'label': row[1][:15],
                'is_guard': bool(row[2]),
                'is_exit': bool(row[3]),
                'bandwidth': row[4] or 0
            })
        
        conn.close()
        
        edges = []
        for i in range(min(20, len(nodes)-1)):
            edges.append({
                'from': nodes[i]['id'],
                'to': nodes[i+1]['id']
            })
        
        return jsonify({'nodes': nodes, 'edges': edges})
    except Exception as e:
        logger.error(f"Error generating network graph: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 70)
    print("TorTrace-AI Dashboard Server")
    print("=" * 70)
    print("\nDashboard available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server\n")
    
    logger.info("Starting Flask application")
    app.run(debug=True, host='0.0.0.0', port=5000)
