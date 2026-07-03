"""
Utility Functions
"""

import hashlib
import re
import os
import json
from datetime import datetime

class Utils:
    @staticmethod
    def sanitize_domain(domain):
        """Clean domain name"""
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        domain = re.sub(r'^www\.', '', domain)
        return domain
    
    @staticmethod
    def get_domain_hash(domain):
        """Generate domain hash"""
        return hashlib.md5(domain.encode()).hexdigest()[:8]
    
    @staticmethod
    def format_size(bytes_size):
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"
    
    @staticmethod
    def format_time(seconds):
        """Format seconds to human readable"""
        if seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            return f"{seconds/60:.2f}m"
        else:
            return f"{seconds/3600:.2f}h"
    
    @staticmethod
    def ensure_dir(directory):
        """Create directory if not exists"""
        if not os.path.exists(directory):
            os.makedirs(directory)
    
    @staticmethod
    def get_security_level(score):
        """Get security level from score"""
        if score >= 90:
            return 'Excellent'
        elif score >= 70:
            return 'Good'
        elif score >= 50:
            return 'Fair'
        elif score >= 30:
            return 'Poor'
        else:
            return 'Critical'