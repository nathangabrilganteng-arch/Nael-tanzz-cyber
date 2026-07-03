"""
HTML Analysis Module
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class HTMLAnalyzer:
    def __init__(self, target, config):
        self.target = target
        self.config = config
    
    def analyze(self):
        results = {
            'url': self.target,
            'html_version': 'unknown',
            'metadata': {},
            'links': {},
            'images': {},
            'favicon': None,
            'robots_txt': None,
            'sitemap_xml': None,
            'broken_links': [],
            'html_validated': False,
            'validation_errors': []
        }
        
        try:
            response = requests.get(
                self.target,
                timeout=10,
                headers={'User-Agent': self.config.get('user_agent', 'Mozilla/5.0')}
            )
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # HTML version
            if soup.find('!DOCTYPE'):
                doctype = str(soup.find('!DOCTYPE')).lower()
                if 'html5' in doctype or 'html' in doctype:
                    results['html_version'] = 'HTML5'
                else:
                    results['html_version'] = 'HTML 4.01'
            
            # Metadata
            title = soup.find('title')
            if title:
                results['metadata']['title'] = title.string.strip() if title.string else ''
            
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                if name:
                    results['metadata'][name] = content
            
            # Links
            internal = []
            external = []
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href:
                    full_url = urljoin(self.target, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc and parsed.netloc not in urlparse(self.target).netloc:
                        external.append(full_url)
                    else:
                        internal.append(full_url)
            
            results['links'] = {
                'internal': len(internal),
                'external': len(external),
                'total': len(internal) + len(external)
            }
            
            # Images
            images = soup.find_all('img')
            with_alt = sum(1 for img in images if img.get('alt'))
            results['images'] = {
                'total': len(images),
                'with_alt': with_alt,
                'without_alt': len(images) - with_alt
            }
            
            # Favicon
            for link in soup.find_all('link'):
                if 'icon' in str(link.get('rel', [])):
                    href = link.get('href')
                    if href:
                        results['favicon'] = urljoin(self.target, href)
                        break
            if not results['favicon']:
                results['favicon'] = urljoin(self.target, '/favicon.ico')
            
            # robots.txt
            try:
                parsed = urlparse(self.target)
                robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
                r = requests.get(robots_url, timeout=5)
                results['robots_txt'] = {'exists': r.status_code == 200}
            except:
                results['robots_txt'] = {'exists': False}
            
            # sitemap.xml
            try:
                parsed = urlparse(self.target)
                sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
                r = requests.get(sitemap_url, timeout=5)
                results['sitemap_xml'] = {'exists': r.status_code == 200}
            except:
                results['sitemap_xml'] = {'exists': False}
            
            # Broken links (check first 10 internal links)
            for link in internal[:10]:
                try:
                    r = requests.head(link, timeout=5, allow_redirects=True)
                    if r.status_code >= 400:
                        results['broken_links'].append({
                            'url': link,
                            'status': r.status_code
                        })
                except:
                    results['broken_links'].append({
                        'url': link,
                        'status': 'timeout'
                    })
            
            # Validation
            errors = []
            # Check for missing alt text
            for img in images:
                if not img.get('alt'):
                    errors.append(f"Missing alt attribute: {img.get('src', 'unknown')}")
            
            results['validation_errors'] = errors[:10]
            results['html_validated'] = len(errors) == 0
            
        except Exception as e:
            results['error'] = str(e)
        
        return results