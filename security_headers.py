"""
Security Headers Analysis Module
"""

import requests
import re
from urllib.parse import urlparse

class SecurityHeadersAnalyzer:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.session = requests.Session()
        self.session.timeout = config.get('scan_timeout', 10)
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'Mozilla/5.0'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
    
    def analyze(self):
        results = {
            'url': self.target,
            'headers': {},
            'security_headers': [],
            'hsts_enabled': False,
            'csp_present': False,
            'x_frame_options': False,
            'x_content_type_options': False,
            'referrer_policy': False,
            'permissions_policy': False,
            'cookies': []
        }
        
        try:
            response = self.session.get(
                self.target,
                allow_redirects=True,
                verify=self.config.get('verify_ssl', True)
            )
            headers = response.headers
            
            # Check HSTS
            if 'Strict-Transport-Security' in headers:
                results['hsts_enabled'] = True
                results['security_headers'].append('HSTS')
                results['headers']['Strict-Transport-Security'] = headers['Strict-Transport-Security']
            
            # Check CSP
            if 'Content-Security-Policy' in headers:
                results['csp_present'] = True
                results['security_headers'].append('CSP')
                results['headers']['Content-Security-Policy'] = headers['Content-Security-Policy']
            
            # Check X-Frame-Options
            if 'X-Frame-Options' in headers:
                results['x_frame_options'] = True
                results['security_headers'].append('X-Frame-Options')
                results['headers']['X-Frame-Options'] = headers['X-Frame-Options']
            
            # Check X-Content-Type-Options
            if 'X-Content-Type-Options' in headers:
                results['x_content_type_options'] = True
                results['security_headers'].append('X-Content-Type-Options')
                results['headers']['X-Content-Type-Options'] = headers['X-Content-Type-Options']
            
            # Check Referrer-Policy
            if 'Referrer-Policy' in headers:
                results['referrer_policy'] = True
                results['security_headers'].append('Referrer-Policy')
                results['headers']['Referrer-Policy'] = headers['Referrer-Policy']
            
            # Check Permissions-Policy
            if 'Permissions-Policy' in headers:
                results['permissions_policy'] = True
                results['security_headers'].append('Permissions-Policy')
                results['headers']['Permissions-Policy'] = headers['Permissions-Policy']
            
            # Cookies
            for cookie in response.cookies:
                results['cookies'].append({
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('httponly')
                })
            
            results['status_code'] = response.status_code
            results['server'] = headers.get('Server', 'unknown')
            
        except Exception as e:
            results['error'] = str(e)
        
        return results