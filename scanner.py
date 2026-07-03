#!/usr/bin/env python3
"""
NAEL SECURITY SCANNER v2.0
Comprehensive Website Security Audit Tool
Author: Nael Security Team
"""

import sys
import os
import argparse
import json
import yaml
import logging
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Import modules
from modules.security_headers import SecurityHeadersAnalyzer
from modules.ssl_tls import SSLTLSInspector
from modules.dns_whois import DNSWhoisChecker
from modules.html_analyzer import HTMLAnalyzer
from modules.performance import PerformanceAnalyzer
from modules.network_scanner import NetworkScanner
from modules.utils import Utils


class NaelScanner:
    """Main Scanner Class"""
    
    def __init__(self, target, config_file='config.yaml'):
        self.target = target
        self.config = self.load_config(config_file)
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'modules': {}
        }
        self.setup_logging()
    
    def load_config(self, config_file):
        """Load configuration"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except:
            return {
                'scan_timeout': 10,
                'max_redirects': 5,
                'user_agent': 'Mozilla/5.0',
                'verify_ssl': True,
                'threads': 4,
                'enable_network_diagnostics': True,
                'modules': {
                    'security_headers': True,
                    'ssl_tls': True,
                    'dns_whois': True,
                    'html': True,
                    'performance': True,
                    'network': True
                }
            }
    
    def setup_logging(self):
        """Setup logging"""
        os.makedirs('logs', exist_ok=True)
        log_file = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def banner(self):
        """Display banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     {Fore.YELLOW}NAEL SECURITY SCANNER v2.0{Fore.CYAN}                          ║
║     {Fore.GREEN}Professional Security Audit Tool{Fore.CYAN}                    ║
╚══════════════════════════════════════════════════════════════╝
{Fore.RESET}
        """
        print(banner)
    
    def run_security_headers(self):
        """Run security headers analysis"""
        print(f"\n{Fore.BLUE}[*] Analyzing Security Headers...{Fore.RESET}")
        analyzer = SecurityHeadersAnalyzer(self.target, self.config)
        return analyzer.analyze()
    
    def run_ssl_tls(self):
        """Run SSL/TLS inspection"""
        print(f"\n{Fore.BLUE}[*] Inspecting SSL/TLS Configuration...{Fore.RESET}")
        inspector = SSLTLSInspector(self.target, self.config)
        return inspector.inspect()
    
    def run_dns_whois(self):
        """Run DNS and WHOIS check"""
        print(f"\n{Fore.BLUE}[*] Checking DNS and WHOIS...{Fore.RESET}")
        checker = DNSWhoisChecker(self.target, self.config)
        return checker.check()
    
    def run_html_analysis(self):
        """Run HTML analysis"""
        print(f"\n{Fore.BLUE}[*] Analyzing HTML Content...{Fore.RESET}")
        analyzer = HTMLAnalyzer(self.target, self.config)
        return analyzer.analyze()
    
    def run_performance(self):
        """Run performance analysis"""
        print(f"\n{Fore.BLUE}[*] Analyzing Performance...{Fore.RESET}")
        analyzer = PerformanceAnalyzer(self.target, self.config)
        return analyzer.analyze()
    
    def run_network(self):
        """Run network diagnostics"""
        if self.config.get('enable_network_diagnostics', True):
            print(f"\n{Fore.BLUE}[*] Running Network Diagnostics...{Fore.RESET}")
            scanner = NetworkScanner(self.config)
            return scanner.diagnose()
        return None
    
    def calculate_score(self):
        """Calculate security score"""
        score = 0
        recommendations = []
        
        # Security Headers (max 25)
        headers = self.results['modules'].get('security_headers', {})
        if headers.get('hsts_enabled'):
            score += 10
        else:
            recommendations.append("Enable HSTS to enforce HTTPS")
        
        if headers.get('csp_present'):
            score += 10
        else:
            recommendations.append("Implement Content Security Policy")
        
        if headers.get('x_frame_options'):
            score += 5
        else:
            recommendations.append("Add X-Frame-Options header")
        
        # SSL/TLS (max 25)
        ssl = self.results['modules'].get('ssl_tls', {})
        if ssl.get('valid_certificate'):
            score += 15
        else:
            recommendations.append("Fix SSL/TLS certificate issues")
        
        if ssl.get('tls_version') in ['TLS 1.3', 'TLS 1.2']:
            score += 10
        else:
            recommendations.append("Upgrade to TLS 1.2 or 1.3")
        
        # DNS/WHOIS (max 15)
        dns = self.results['modules'].get('dns_whois', {})
        if not dns.get('domain_expiring_soon', False):
            score += 15
        else:
            recommendations.append(f"Domain expiring soon: {dns.get('expiration_date', 'unknown')}")
        
        # HTML (max 15)
        html = self.results['modules'].get('html', {})
        if html.get('html_validated', False):
            score += 5
        if len(html.get('broken_links', [])) == 0:
            score += 10
        else:
            recommendations.append(f"Fix {len(html.get('broken_links', []))} broken links")
        
        # Performance (max 10)
        perf = self.results['modules'].get('performance', {})
        if perf.get('load_time', 10) < 3:
            score += 5
        if perf.get('page_size_kb', 2000) < 1000:
            score += 5
        
        # Network (max 10)
        network = self.results['modules'].get('network', {})
        if network and network.get('latency'):
            if network.get('latency') < 50:
                score += 5
            if network.get('signal_strength', 0) > 50:
                score += 5
        
        # Normalize
        score = min(score, 100)
        
        # Grade
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return {
            'score': score,
            'grade': grade,
            'recommendations': recommendations[:10]
        }
    
    def run_full_scan(self):
        """Run all modules"""
        self.banner()
        
        print(f"\n{Fore.GREEN}[+] Target: {self.target}{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Starting comprehensive security audit...{Fore.RESET}\n")
        
        # Module list
        modules = [
            ('security_headers', 'Security Headers'),
            ('ssl_tls', 'SSL/TLS'),
            ('dns_whois', 'DNS & WHOIS'),
            ('html', 'HTML Analysis'),
            ('performance', 'Performance'),
            ('network', 'Network')
        ]
        
        # Run with progress bar
        with tqdm(total=len(modules), desc="Scanning Progress", 
                 bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            
            for module_name, display_name in modules:
                if self.config.get('modules', {}).get(module_name, True):
                    method = getattr(self, f'run_{module_name}')
                    self.results['modules'][module_name] = method()
                    pbar.update(1)
        
        # Calculate score
        score_result = self.calculate_score()
        self.results['security_score'] = score_result
        
        # Display summary
        self.display_summary(score_result)
        
        # Export results
        self.export_results()
        
        return self.results
    
    def display_summary(self, score_result):
        """Display scan summary"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║              {Fore.YELLOW}SCAN SUMMARY{Fore.CYAN}                                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Fore.RESET}")
        
        score = score_result['score']
        grade = score_result['grade']
        
        # Color based on grade
        if grade == 'A':
            color = Fore.GREEN
        elif grade in ['B', 'C']:
            color = Fore.YELLOW
        else:
            color = Fore.RED
        
        print(f"\n{color}[+] Security Score: {score}/100 ({grade}){Fore.RESET}")
        
        # Recommendations
        if score_result['recommendations']:
            print(f"\n{Fore.YELLOW}[!] Recommendations:{Fore.RESET}")
            for rec in score_result['recommendations']:
                print(f"  {Fore.YELLOW}•{Fore.RESET} {rec}")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical issues found!{Fore.RESET}")
        
        # Quick stats
        print(f"\n{Fore.CYAN}Quick Stats:{Fore.RESET}")
        headers = self.results['modules'].get('security_headers', {})
        ssl = self.results['modules'].get('ssl_tls', {})
        perf = self.results['modules'].get('performance', {})
        
        print(f"  - HTTPS: {Fore.GREEN if ssl.get('https_enabled') else Fore.RED}{'✓' if ssl.get('https_enabled') else '✗'}{Fore.RESET}")
        print(f"  - HSTS: {Fore.GREEN if headers.get('hsts_enabled') else Fore.RED}{'✓' if headers.get('hsts_enabled') else '✗'}{Fore.RESET}")
        print(f"  - CSP: {Fore.GREEN if headers.get('csp_present') else Fore.RED}{'✓' if headers.get('csp_present') else '✗'}{Fore.RESET}")
        print(f"  - Valid SSL: {Fore.GREEN if ssl.get('valid_certificate') else Fore.RED}{'✓' if ssl.get('valid_certificate') else '✗'}{Fore.RESET}")
        print(f"  - Load Time: {Fore.CYAN}{perf.get('load_time', 0):.2f}s{Fore.RESET}")
        print(f"  - Page Size: {Fore.CYAN}{perf.get('page_size_kb', 0):.1f}KB{Fore.RESET}")
        
        print(f"\n{Fore.GREEN}[+] Reports saved to: reports/{Fore.RESET}")
    
    def export_results(self):
        """Export results"""
        os.makedirs('reports', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
        base_name = f"{domain}_{timestamp}"
        
        # JSON export
        if 'json' in self.config.get('export_formats', ['json', 'html']):
            json_file = f"reports/{base_name}.json"
            with open(json_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"[+] JSON report: {json_file}")
        
        # HTML export
        if 'html' in self.config.get('export_formats', ['json', 'html']):
            html_file = f"reports/{base_name}.html"
            self.export_html(html_file)
            print(f"[+] HTML report: {html_file}")
    
    def export_html(self, filename):
        """Export HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Report - {{ target }}</title>
            <style>
                body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 40px; background: #0a0a0f; color: #e0e0e0; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 30px; border-radius: 15px; border: 1px solid #00ff41; box-shadow: 0 0 30px rgba(0,255,65,0.1); }
                .header h1 { color: #00ff41; margin: 0; font-size: 28px; }
                .header p { color: #888; margin: 5px 0; }
                .score-section { text-align: center; padding: 40px 0; }
                .score-number { font-size: 80px; font-weight: bold; }
                .score-grade { font-size: 40px; margin-left: 20px; }
                .grade-A { color: #00ff41; }
                .grade-B { color: #00ccff; }
                .grade-C { color: #ffd700; }
                .grade-D { color: #ff6b00; }
                .grade-F { color: #ff0000; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
                .stat-card { background: #1a1a2e; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #333; }
                .stat-value { font-size: 32px; font-weight: bold; }
                .stat-label { color: #888; font-size: 14px; margin-top: 5px; }
                .section { background: #1a1a2e; padding: 25px; margin: 20px 0; border-radius: 10px; border: 1px solid #333; }
                .section h2 { color: #00ff41; margin-top: 0; }
                .recommendation { padding: 12px; margin: 8px 0; background: #2a2a3e; border-radius: 8px; border-left: 4px solid #ffd700; }
                .recommendation.critical { border-left-color: #ff0000; }
                .recommendation.success { border-left-color: #00ff41; }
                .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }
                .badge-success { background: #00ff41; color: #000; }
                .badge-danger { background: #ff0000; color: #fff; }
                .badge-warning { background: #ffd700; color: #000; }
                .badge-info { background: #00ccff; color: #000; }
                table { width: 100%; border-collapse: collapse; margin: 15px 0; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
                th { background: #00ff41; color: #000; }
                tr:hover { background: #2a2a3e; }
                .footer { text-align: center; margin-top: 40px; color: #666; font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Nael Security Report</h1>
                    <p>Target: <strong>{{ target }}</strong></p>
                    <p>Scan Date: {{ timestamp }}</p>
                </div>
                
                <div class="score-section">
                    <span class="score-number">{{ score }}</span>
                    <span class="score-grade grade-{{ grade }}">({{ grade }})</span>
                    <p style="color: #888; font-size: 18px;">Security Score</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value" style="color: {{ '#' if https else '#ff0000' }}">{{ '✅' if https else '❌' }}</div>
                        <div class="stat-label">HTTPS</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: {{ '#' if hsts else '#ff0000' }}">{{ '✅' if hsts else '❌' }}</div>
                        <div class="stat-label">HSTS</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: {{ '#' if csp else '#ff0000' }}">{{ '✅' if csp else '❌' }}</div>
                        <div class="stat-label">CSP</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: {{ '#' if ssl_valid else '#ff0000' }}">{{ '✅' if ssl_valid else '❌' }}</div>
                        <div class="stat-label">SSL Valid</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ load_time }}s</div>
                        <div class="stat-label">Load Time</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ page_size }}KB</div>
                        <div class="stat-label">Page Size</div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>⚠️ Recommendations</h2>
                    {% if recommendations %}
                        {% for rec in recommendations %}
                        <div class="recommendation">{{ rec }}</div>
                        {% endfor %}
                    {% else %}
                        <div style="color: #00ff41; font-size: 18px;">✅ No issues found! Your website is secure.</div>
                    {% endif %}
                </div>
                
                <div class="section">
                    <h2>📊 Module Results</h2>
                    <table>
                        <tr>
                            <th>Module</th>
                            <th>Status</th>
                            <th>Details</th>
                        </tr>
                        <tr>
                            <td>Security Headers</td>
                            <td><span class="badge {{ 'badge-success' if headers_passed else 'badge-warning' }}">{{ 'PASSED' if headers_passed else 'WARNING' }}</span></td>
                            <td>{{ headers_found }} headers found</td>
                        </tr>
                        <tr>
                            <td>SSL/TLS</td>
                            <td><span class="badge {{ 'badge-success' if ssl_passed else 'badge-danger' }}">{{ 'PASSED' if ssl_passed else 'FAILED' }}</span></td>
                            <td>{{ tls_version }}</td>
                        </tr>
                        <tr>
                            <td>DNS/WHOIS</td>
                            <td><span class="badge {{ 'badge-success' if dns_passed else 'badge-warning' }}">{{ 'PASSED' if dns_passed else 'WARNING' }}</span></td>
                            <td>{{ dns_status }}</td>
                        </tr>
                        <tr>
                            <td>HTML Analysis</td>
                            <td><span class="badge {{ 'badge-success' if html_passed else 'badge-warning' }}">{{ 'PASSED' if html_passed else 'WARNING' }}</span></td>
                            <td>{{ html_status }}</td>
                        </tr>
                        <tr>
                            <td>Performance</td>
                            <td><span class="badge {{ 'badge-success' if perf_passed else 'badge-warning' }}">{{ 'PASSED' if perf_passed else 'WARNING' }}</span></td>
                            <td>{{ perf_status }}</td>
                        </tr>
                    </table>
                </div>
                
                <div class="footer">
                    Generated by Nael Security Scanner v2.0 | {{ timestamp }}
                </div>
            </div>
        </body>
        </html>
        """
        
        from jinja2 import Template
        
        # Prepare data
        headers = self.results['modules'].get('security_headers', {})
        ssl = self.results['modules'].get('ssl_tls', {})
        dns = self.results['modules'].get('dns_whois', {})
        html = self.results['modules'].get('html', {})
        perf = self.results['modules'].get('performance', {})
        
        template = Template(html_template)
        html_content = template.render(
            target=self.target,
            timestamp=self.results['timestamp'],
            score=self.results['security_score']['score'],
            grade=self.results['security_score']['grade'],
            recommendations=self.results['security_score']['recommendations'],
            https=ssl.get('https_enabled', False),
            hsts=headers.get('hsts_enabled', False),
            csp=headers.get('csp_present', False),
            ssl_valid=ssl.get('valid_certificate', False),
            load_time=round(perf.get('load_time', 0), 2),
            page_size=round(perf.get('page_size_kb', 0), 1),
            headers_passed=headers.get('hsts_enabled', False) or headers.get('csp_present', False),
            headers_found=len(headers.get('security_headers', [])),
            ssl_passed=ssl.get('valid_certificate', False),
            tls_version=ssl.get('tls_version', 'Unknown'),
            dns_passed=not dns.get('domain_expiring_soon', True),
            dns_status=f"Expires: {dns.get('expiration_date', 'Unknown')}",
            html_passed=html.get('html_validated', False),
            html_status=f"{len(html.get('broken_links', []))} broken links",
            perf_passed=perf.get('load_time', 10) < 3,
            perf_status=f"{round(perf.get('load_time', 0), 2)}s load time"
        )
        
        with open(filename, 'w') as f:
            f.write(html_content)


def main():
    parser = argparse.ArgumentParser(
        description='Nael Security Scanner - Advanced Security Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('target', help='Target domain or URL (e.g., example.com)')
    parser.add_argument('--config', '-c', default='config.yaml', help='Configuration file')
    parser.add_argument('--skip-network', action='store_true', help='Skip network diagnostics')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', 
                       help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target
    
    # Create scanner instance
    scanner = NaelScanner(args.target, args.config)
    
    # Apply options
    if args.skip_network:
        scanner.config['enable_network_diagnostics'] = False
    
    if args.format != 'both':
        scanner.config['export_formats'] = [args.format]
    
    # Run scan
    try:
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Fore.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Fore.RESET}")
        logging.error(f"Scan error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()