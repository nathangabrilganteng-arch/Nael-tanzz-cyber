"""
Performance Analysis Module
"""

import requests
import time
from bs4 import BeautifulSoup

class PerformanceAnalyzer:
    def __init__(self, target, config):
        self.target = target
        self.config = config
    
    def analyze(self):
        results = {
            'page_size': 0,
            'page_size_kb': 0,
            'load_time': 0,
            'time_to_first_byte': 0,
            'status_code': 0,
            'redirect_count': 0,
            'resource_stats': {
                'images': 0,
                'css': 0,
                'javascript': 0,
                'total': 0
            },
            'recommendations': []
        }
        
        try:
            start_time = time.time()
            response = requests.get(
                self.target,
                headers={'User-Agent': self.config.get('user_agent', 'Mozilla/5.0')}
            )
            end_time = time.time()
            
            results['load_time'] = end_time - start_time
            results['status_code'] = response.status_code
            results['redirect_count'] = len(response.history)
            results['time_to_first_byte'] = response.elapsed.total_seconds()
            
            # Page size
            content = response.content
            results['page_size'] = len(content)
            results['page_size_kb'] = len(content) / 1024
            
            # Resource stats
            soup = BeautifulSoup(content, 'html.parser')
            results['resource_stats']['images'] = len(soup.find_all('img'))
            results['resource_stats']['css'] = len(soup.find_all('link', {'rel': 'stylesheet'}))
            results['resource_stats']['javascript'] = len(soup.find_all('script'))
            results['resource_stats']['total'] = (
                results['resource_stats']['images'] +
                results['resource_stats']['css'] +
                results['resource_stats']['javascript'] +
                1
            )
            
            # Recommendations
            if results['page_size_kb'] > 1000:
                results['recommendations'].append("Page is large (>1MB), optimize resources")
            if results['load_time'] > 3:
                results['recommendations'].append(f"Load time is {results['load_time']:.2f}s, improve performance")
            if results['resource_stats']['images'] > 50:
                results['recommendations'].append("Many images found, consider lazy loading")
            
        except Exception as e:
            results['error'] = str(e)
        
        return results