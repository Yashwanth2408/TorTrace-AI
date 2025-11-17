#!/usr/bin/env python3
"""
TorTrace-AI: Geographic Location Service
Resolves IP addresses to geographic coordinates
"""

import socket
import json
import os
from typing import Dict, Tuple, Optional
import requests

class GeoLocator:
    """IP to Geographic location resolver"""
    
    def __init__(self, cache_file='data/geo_cache.json'):
        """Initialize with optional cache"""
        self.cache_file = cache_file
        self.cache = self._load_cache()
    
    def _load_cache(self) -> Dict:
        """Load cached locations"""
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_cache(self):
        """Save cache to disk"""
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def get_location(self, ip_address: str) -> Optional[Dict]:
        """
        Get geographic location for IP address
        
        Returns:
            Dict with lat, lon, country, city or None
        """
        # Check cache first
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        try:
            # Use ip-api.com (free, no key required)
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    location = {
                        'ip': ip_address,
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'isp': data.get('isp', 'Unknown')
                    }
                    
                    # Cache it
                    self.cache[ip_address] = location
                    self._save_cache()
                    
                    return location
        except Exception as e:
            print(f"Error getting location for {ip_address}: {e}")
        
        return None
    
    def get_country_stats(self, locations: list) -> Dict:
        """Get statistics by country"""
        country_counts = {}
        
        for loc in locations:
            country = loc.get('country', 'Unknown')
            country_counts[country] = country_counts.get(country, 0) + 1
        
        return country_counts
