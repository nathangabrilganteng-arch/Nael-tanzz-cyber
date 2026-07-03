"""
Network Diagnostics Module
"""

import subprocess
import platform
import re
import socket
import requests
import time

class NetworkScanner:
    def __init__(self, config):
        self.config = config
        self.os_type = platform.system()
    
    def diagnose(self):
        results = {
            'ssid': None,
            'ip_address': None,
            'gateway': None,
            'dns_servers': None,
            'latency': None,
            'signal_strength': None,
            'os': self.os_type
        }
        
        # Get network info based on OS
        if self.os_type == 'Linux':
            results.update(self._get_linux_info())
        elif self.os_type == 'Windows':
            results.update(self._get_windows_info())
        else:
            results['error'] = f"Unsupported OS: {self.os_type}"
        
        # Latency test
        try:
            if self.os_type == 'Windows':
                cmd = ['ping', '-n', '4', '8.8.8.8']
            else:
                cmd = ['ping', '-c', '4', '8.8.8.8']
            
            result = subprocess.check_output(cmd, text=True, timeout=10)
            avg_match = re.search(r'avg = (\d+\.?\d*)', result)
            if avg_match:
                results['latency'] = float(avg_match.group(1))
        except:
            results['latency'] = None
        
        return results
    
    def _get_linux_info(self):
        info = {}
        try:
            # SSID
            try:
                ssid = subprocess.check_output(['iwgetid', '-r'], text=True).strip()
                if ssid:
                    info['ssid'] = ssid
            except:
                info['ssid'] = 'Unknown'
            
            # IP Address
            try:
                hostname = socket.gethostname()
                info['ip_address'] = socket.gethostbyname(hostname)
            except:
                info['ip_address'] = None
            
            # Gateway
            try:
                gw = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
                gw_match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', gw)
                info['gateway'] = gw_match.group(1) if gw_match else None
            except:
                info['gateway'] = None
            
            # DNS
            try:
                dns = subprocess.check_output(['cat', '/etc/resolv.conf'], text=True)
                dns_servers = re.findall(r'nameserver\s+(\d+\.\d+\.\d+\.\d+)', dns)
                info['dns_servers'] = dns_servers[:3] if dns_servers else ['Not found']
            except:
                info['dns_servers'] = ['Not found']
            
            # Signal strength
            try:
                signal = subprocess.check_output(['cat', '/proc/net/wireless'], text=True)
                signal_match = re.search(r'wlan0:\s+\d+\s+(\d+)', signal)
                if signal_match:
                    info['signal_strength'] = int(signal_match.group(1))
            except:
                pass
                
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def _get_windows_info(self):
        info = {}
        try:
            # SSID
            try:
                result = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], 
                                               text=True, shell=True)
                ssid_match = re.search(r'SSID\s+:\s+(.+)', result)
                info['ssid'] = ssid_match.group(1).strip() if ssid_match else 'Unknown'
            except:
                info['ssid'] = 'Unknown'
            
            # IP Address
            try:
                hostname = socket.gethostname()
                info['ip_address'] = socket.gethostbyname(hostname)
            except:
                info['ip_address'] = None
                
        except Exception as e:
            info['error'] = str(e)
        
        return info