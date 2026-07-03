"""
SSL/TLS Inspection Module
"""

import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse

class SSLTLSInspector:
    def __init__(self, target, config):
        self.target = target
        self.config = config
    
    def inspect(self):
        results = {
            'https_enabled': False,
            'valid_certificate': False,
            'certificate_details': {},
            'tls_version': 'unknown'
        }
        
        parsed = urlparse(self.target)
        hostname = parsed.hostname or self.target
        
        # Check HTTPS
        try:
            test_url = f"https://{hostname}"
            response = requests.get(test_url, timeout=10, verify=True)
            results['https_enabled'] = True
        except:
            results['https_enabled'] = False
            return results
        
        # Get SSL certificate
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['tls_version'] = ssock.version()
                    cert = ssock.getpeercert()
                    
                    if cert:
                        results['valid_certificate'] = True
                        results['certificate_details'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter')
                        }
                        
                        # Check expiration
                        if cert.get('notAfter'):
                            not_after = datetime.datetime.strptime(
                                cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z'
                            )
                            days_left = (not_after - datetime.datetime.now()).days
                            results['days_until_expiry'] = days_left
        except Exception as e:
            results['ssl_error'] = str(e)
        
        return results