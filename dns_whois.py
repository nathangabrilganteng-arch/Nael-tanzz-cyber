"""
DNS and WHOIS Module
"""

import dns.resolver
import whois
from urllib.parse import urlparse
import datetime

class DNSWhoisChecker:
    def __init__(self, target, config):
        self.target = target
        self.config = config
    
    def check(self):
        results = {
            'domain': '',
            'dns_records': {},
            'whois': {},
            'domain_expiring_soon': False,
            'expiration_date': None
        }
        
        parsed = urlparse(self.target)
        domain = parsed.hostname or self.target
        results['domain'] = domain
        
        # DNS Records
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results['dns_records'][record_type] = [str(r) for r in answers]
            except:
                results['dns_records'][record_type] = []
        
        # WHOIS
        try:
            w = whois.whois(domain)
            results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers
            }
            
            if w.expiration_date:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0]
                results['expiration_date'] = str(exp)
                
                if isinstance(exp, datetime.datetime):
                    days_left = (exp - datetime.datetime.now()).days
                    results['domain_expiring_soon'] = days_left < 30
        except:
            pass
        
        return results