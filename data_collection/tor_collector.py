#!/usr/bin/env python3
"""
TorTrace-AI: Tor Network Data Collector

Collects and stores Tor relay information from the network consensus.
Provides real-time network topology data for correlation analysis.
"""

import sqlite3
import logging
from datetime import datetime
from stem.control import Controller
from stem import Flag

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TorCollector:
    """
    Tor network data collector.
    
    Interfaces with Tor control port to retrieve relay descriptors
    and network consensus information. Stores data in SQLite database
    for downstream analysis.
    """
    
    def __init__(self, db_path='../data/tor_relays.db'):
        """
        Initialize collector with database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create database schema if not exists."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS relays (
                fingerprint TEXT PRIMARY KEY,
                nickname TEXT,
                address TEXT,
                or_port INTEGER,
                dir_port INTEGER,
                flags TEXT,
                bandwidth INTEGER,
                consensus_weight INTEGER,
                country TEXT,
                is_guard INTEGER,
                is_exit INTEGER,
                is_fast INTEGER,
                is_stable INTEGER,
                last_seen TIMESTAMP,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collection_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_relays INTEGER,
                guard_relays INTEGER,
                exit_relays INTEGER,
                total_bandwidth INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def collect_relays(self):
        """
        Collect current Tor relay information from network consensus.
        
        Returns:
            list: List of relay information dictionaries
        """
        logger.info("Connecting to Tor control port")
        
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                logger.info("Connected to Tor network")
                
                relays_data = []
                guard_count = 0
                exit_count = 0
                total_bandwidth = 0
                
                for desc in controller.get_network_statuses():
                    flags = [str(flag) for flag in desc.flags]
                    
                    is_guard = 1 if Flag.GUARD in desc.flags else 0
                    is_exit = 1 if Flag.EXIT in desc.flags else 0
                    is_fast = 1 if Flag.FAST in desc.flags else 0
                    is_stable = 1 if Flag.STABLE in desc.flags else 0
                    
                    bandwidth = desc.bandwidth if hasattr(desc, 'bandwidth') else 0
                    
                    relay_info = {
                        'fingerprint': desc.fingerprint,
                        'nickname': desc.nickname,
                        'address': desc.address,
                        'or_port': desc.or_port,
                        'dir_port': desc.dir_port if hasattr(desc, 'dir_port') else 0,
                        'flags': ','.join(flags),
                        'bandwidth': bandwidth,
                        'consensus_weight': 0,
                        'country': 'XX',
                        'is_guard': is_guard,
                        'is_exit': is_exit,
                        'is_fast': is_fast,
                        'is_stable': is_stable,
                        'last_seen': datetime.now().isoformat()
                    }
                    
                    relays_data.append(relay_info)
                    
                    if is_guard:
                        guard_count += 1
                    if is_exit:
                        exit_count += 1
                    total_bandwidth += bandwidth
                
                logger.info(f"Collected {len(relays_data)} relays")
                logger.info(f"Guard relays: {guard_count}, Exit relays: {exit_count}")
                logger.info(f"Total bandwidth: {total_bandwidth / 1024 / 1024:.2f} MB/s")
                
                self.save_relays(relays_data, guard_count, exit_count, total_bandwidth)
                
                return relays_data
                
        except Exception as e:
            logger.error(f"Error collecting relays: {e}")
            return []
    
    def save_relays(self, relays_data, guard_count, exit_count, total_bandwidth):
        """
        Save relay data to database.
        
        Args:
            relays_data: List of relay information dictionaries
            guard_count: Number of guard relays
            exit_count: Number of exit relays
            total_bandwidth: Total network bandwidth
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for relay in relays_data:
            cursor.execute('''
                INSERT OR REPLACE INTO relays 
                (fingerprint, nickname, address, or_port, dir_port, flags, 
                 bandwidth, consensus_weight, country, is_guard, is_exit, 
                 is_fast, is_stable, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                relay['fingerprint'], relay['nickname'], relay['address'],
                relay['or_port'], relay['dir_port'], relay['flags'],
                relay['bandwidth'], relay['consensus_weight'], relay['country'],
                relay['is_guard'], relay['is_exit'], relay['is_fast'],
                relay['is_stable'], relay['last_seen']
            ))
        
        cursor.execute('''
            INSERT INTO collection_stats 
            (total_relays, guard_relays, exit_relays, total_bandwidth)
            VALUES (?, ?, ?, ?)
        ''', (len(relays_data), guard_count, exit_count, total_bandwidth))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Saved {len(relays_data)} relays to database")
    
    def get_statistics(self):
        """
        Get current Tor network statistics from database.
        
        Returns:
            dict: Network statistics
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
            'guard_relays': guards,
            'exit_relays': exits,
            'total_bandwidth': bandwidth
        }
    
    def get_guard_nodes(self, limit=50):
        """
        Get top guard nodes by bandwidth.
        
        Args:
            limit: Maximum number of guards to return
            
        Returns:
            list: Guard node information tuples
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT fingerprint, nickname, address, bandwidth, flags
            FROM relays
            WHERE is_guard = 1
            ORDER BY bandwidth DESC
            LIMIT ?
        ''', (limit,))
        
        guards = cursor.fetchall()
        conn.close()
        
        return guards


def main():
    """Main execution routine."""
    print("=" * 70)
    print("TorTrace-AI: Tor Network Data Collector")
    print("=" * 70)
    
    collector = TorCollector()
    
    # Collect relay data
    relays = collector.collect_relays()
    
    if relays:
        # Display statistics
        print("\nNetwork Statistics:")
        stats = collector.get_statistics()
        print(f"  Total relays: {stats['total_relays']}")
        print(f"  Guard relays: {stats['guard_relays']}")
        print(f"  Exit relays: {stats['exit_relays']}")
        print(f"  Total bandwidth: {stats['total_bandwidth'] / 1024 / 1024:.2f} MB/s")
        
        # Show top guard nodes
        print("\nTop 10 Guard Nodes:")
        guards = collector.get_guard_nodes(10)
        for i, guard in enumerate(guards, 1):
            print(f"  {i:2d}. {guard[1][:20]:20s} | {guard[2]:15s} | {guard[3]/1024:.2f} KB/s")
        
        print(f"\nData collection complete. Database: {collector.db_path}")
    else:
        print("\nNo data collected")


if __name__ == "__main__":
    main()
