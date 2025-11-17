#!/usr/bin/env python3
"""
TorTrace-AI: Interactive Map Generator
Creates beautiful geographic visualizations of guard nodes
"""

import folium
from folium import plugins
import csv
import json
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.geo_locator import GeoLocator

class TorMapGenerator:
    """Generate interactive maps of Tor guard nodes"""
    
    def __init__(self):
        """Initialize map generator"""
        self.geo = GeoLocator()
        self.guard_locations = []
    
    def load_results(self, csv_file: str):
        """Load guard node results from CSV"""
        guards = {}
        
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                nickname = row['Relay Nickname']
                ip = row['IP Address']
                confidence = float(row['Confidence'])
                
                if nickname not in guards:
                    guards[nickname] = {
                        'nickname': nickname,
                        'ip': ip,
                        'max_confidence': confidence,
                        'detections': 1
                    }
                else:
                    guards[nickname]['detections'] += 1
                    guards[nickname]['max_confidence'] = max(
                        guards[nickname]['max_confidence'],
                        confidence
                    )
        
        # Get locations for all guards
        for guard in guards.values():
            location = self.geo.get_location(guard['ip'])
            if location:
                guard['location'] = location
                self.guard_locations.append(guard)
            else:
                print(f"Could not locate {guard['nickname']} ({guard['ip']})")
        
        print(f"Located {len(self.guard_locations)} guard nodes")
        return self.guard_locations
    
    def create_map(self, output_file='templates/tor_map.html'):
        """Create interactive Folium map"""
        
        if not self.guard_locations:
            print("No guard locations to map!")
            return
        
        # Calculate map center (average of all locations)
        avg_lat = sum(g['location']['lat'] for g in self.guard_locations) / len(self.guard_locations)
        avg_lon = sum(g['location']['lon'] for g in self.guard_locations) / len(self.guard_locations)
        
        # Create map centered on average location
        m = folium.Map(
            location=[avg_lat, avg_lon],
            zoom_start=3,
            tiles='CartoDB dark_matter',  # Dark theme
            control_scale=True
        )
        
        # Add markers for each guard node
        for guard in self.guard_locations:
            loc = guard['location']
            confidence = guard['max_confidence']
            
            # Color based on confidence
            if confidence >= 90:
                color = 'red'
                icon_name = 'exclamation-triangle'
            elif confidence >= 80:
                color = 'orange'
                icon_name = 'warning'
            else:
                color = 'yellow'
                icon_name = 'info-sign'
            
            # Popup content
            popup_html = f"""
            <div style="font-family: monospace; min-width: 200px;">
                <h4 style="color: #ff0000; margin-bottom: 5px;">{guard['nickname']}</h4>
                <table style="width: 100%; font-size: 12px;">
                    <tr><td><b>IP:</b></td><td>{guard['ip']}</td></tr>
                    <tr><td><b>Confidence:</b></td><td><span style="color: {color};">{confidence}%</span></td></tr>
                    <tr><td><b>Detections:</b></td><td>{guard['detections']}</td></tr>
                    <tr><td><b>Country:</b></td><td>{loc['country']}</td></tr>
                    <tr><td><b>City:</b></td><td>{loc['city']}</td></tr>
                    <tr><td><b>ISP:</b></td><td>{loc['isp']}</td></tr>
                </table>
            </div>
            """
            
            folium.Marker(
                location=[loc['lat'], loc['lon']],
                popup=folium.Popup(popup_html, max_width=300),
                tooltip=f"{guard['nickname']} ({confidence}%)",
                icon=folium.Icon(color=color, icon=icon_name, prefix='glyphicon')
            ).add_to(m)
        
        # Add circle markers for better visibility
        for guard in self.guard_locations:
            loc = guard['location']
            confidence = guard['max_confidence']
            
            # Size based on confidence
            radius = 5 + (confidence / 10)
            
            folium.CircleMarker(
                location=[loc['lat'], loc['lon']],
                radius=radius,
                color='#ff0000',
                fill=True,
                fillColor='#ff0000',
                fillOpacity=0.3,
                weight=2
            ).add_to(m)
        
        # Add heatmap layer
        heat_data = [[g['location']['lat'], g['location']['lon']] for g in self.guard_locations]
        plugins.HeatMap(heat_data, radius=25, blur=35, max_zoom=1, gradient={
            0.0: 'blue',
            0.5: 'yellow',
            1.0: 'red'
        }).add_to(m)
        
        # Add country statistics
        country_stats = self.geo.get_country_stats([g['location'] for g in self.guard_locations])
        stats_html = "<h3>Guard Nodes by Country</h3><ul>"
        for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
            stats_html += f"<li><b>{country}:</b> {count}</li>"
        stats_html += "</ul>"
        
        # Save map
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        m.save(output_file)
        
        print(f"\n✅ Interactive map saved to {output_file}")
        print(f"📊 {len(self.guard_locations)} guard nodes mapped across {len(country_stats)} countries")
        
        return output_file

def main():
    """Generate map from batch results"""
    import os
    csv_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'batch_results', 'batch_summary.csv')

    
    if not os.path.exists(csv_file):
        print(f"❌ Error: {csv_file} not found!")
        print("Run batch_analyzer.py first to generate results.")
        return
    
    print("="*70)
    print("TorTrace-AI: Geographic Map Generator")
    print("="*70)
    
    generator = TorMapGenerator()
    generator.load_results(csv_file)
    generator.create_map()
    
    print("="*70)

if __name__ == '__main__':
    main()
