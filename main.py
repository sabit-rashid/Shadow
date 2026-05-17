#!/usr/bin/env python3
"""
Automated Reconnaissance & Vulnerability Scanner
Author: Security Assessment Tool
Version: 1.0.0
License: MIT (Educational Use Only)
"""

import argparse
import asyncio
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import hashlib

# Third-party imports
try:
    import aiohttp
    import dns.resolver
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    import whois
    from tqdm import tqdm
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Install with: pip install aiohttp dnspython requests beautifulsoup4 colorama python-whois tqdm")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

class Colors:
    """Color codes for console output"""
    INFO = Fore.CYAN
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    CRITICAL = Fore.MAGENTA
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class Logger:
    """Custom logging with colors and levels"""
    
    @staticmethod
    def info(msg: str):
        print(f"{Colors.INFO}[INFO]{Colors.RESET} {msg}")
    
    @staticmethod
    def success(msg: str):
        print(f"{Colors.SUCCESS}[SUCCESS]{Colors.RESET} {msg}")
    
    @staticmethod
    def warning(msg: str):
        print(f"{Colors.WARNING}[WARNING]{Colors.RESET} {msg}")
    
    @staticmethod
    def error(msg: str):
        print(f"{Colors.ERROR}[ERROR]{Colors.RESET} {msg}")
    
    @staticmethod
    def critical(msg: str):
        print(f"{Colors.CRITICAL}[CRITICAL]{Colors.RESET} {msg}")

class Reconnaissance:
    """Handles all reconnaissance activities"""
    
    def __init__(self, target: str, threads: int = 10):
        self.target = target
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'dns': {},
            'subdomains': [],
            'technologies': [],
            'ports': [],
            'headers': {},
            'endpoints': set(),
            'js_files': set(),
            'parameters': set(),
            'forms': []
        }
    
    def normalize_target(self) -> str:
        """Normalize the target URL/domain"""
        if not self.target.startswith(('http://', 'https://')):
            self.target = f'https://{self.target}'
        parsed = urlparse(self.target)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def dns_enumeration(self) -> Dict:
        """Perform DNS enumeration"""
        Logger.info("Performing DNS enumeration...")
        domain = urlparse(self.normalize_target()).netloc
        
        try:
            # A records
            a_records = dns.resolver.resolve(domain, 'A')
            self.results['dns']['a_records'] = [str(r) for r in a_records]
            
            # AAAA records
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                self.results['dns']['aaaa_records'] = [str(r) for r in aaaa_records]
            except:
                self.results['dns']['aaaa_records'] = []
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                self.results['dns']['mx_records'] = [str(r.exchange) for r in mx_records]
            except:
                self.results['dns']['mx_records'] = []
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                self.results['dns']['ns_records'] = [str(r) for r in ns_records]
            except:
                self.results['dns']['ns_records'] = []
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                self.results['dns']['txt_records'] = [str(r) for r in txt_records]
            except:
                self.results['dns']['txt_records'] = []
            
            Logger.success(f"Found {len(self.results['dns'].get('a_records', []))} A records")
        except Exception as e:
            Logger.error(f"DNS enumeration failed: {e}")
        
        return self.results['dns']
    
    def subdomain_enumeration(self, wordlist_path: str = None):
        """Enumerate subdomains"""
        Logger.info("Enumerating subdomains...")
        domain = urlparse(self.normalize_target()).netloc
        
        # Common subdomains wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
            'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover',
            'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'shop',
            'dev', 'staging', 'admin', 'api', 'cdn', 'mobile', 'secure',
            'vpn', 'dns', 'remote', 'portal', 'support', 'help', 'docs'
        ]
        
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                common_subdomains = [line.strip() for line in f if line.strip()]
        
        found_subdomains = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for sub in common_subdomains:
                futures.append(executor.submit(self._check_subdomain, domain, sub))
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Checking subdomains"):
                result = future.result()
                if result:
                    found_subdomains.append(result)
        
        self.results['subdomains'] = found_subdomains
        Logger.success(f"Found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    def _check_subdomain(self, domain: str, subdomain: str) -> Optional[str]:
        """Check if subdomain exists"""
        subdomain_url = f"{subdomain}.{domain}"
        try:
            socket.gethostbyname(subdomain_url)
            return subdomain_url
        except:
            return None
    
    def port_scanning(self, ports: List[int] = None):
        """Scan for open ports"""
        Logger.info("Scanning for open ports...")
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080, 8443]
        
        domain = urlparse(self.normalize_target()).netloc
        open_ports = []
        
        def scan_port(port: int) -> Optional[int]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append({
                        'port': result,
                        'service': socket.getservbyport(result) if result < 1024 else 'unknown'
                    })
        
        self.results['ports'] = open_ports
        Logger.success(f"Found {len(open_ports)} open ports")
        return open_ports
    
    def technology_detection(self):
        """Detect technologies used by the target"""
        Logger.info("Detecting technologies...")
        target_url = self.normalize_target()
        
        try:
            response = self.session.get(target_url, timeout=10, verify=False)
            technologies = []
            
            # Check headers
            headers = response.headers
            
            # Common technology signatures
            tech_signatures = {
                'X-Powered-By': lambda v: v,
                'Server': lambda v: v,
                'X-Generator': lambda v: v,
                'X-Drupal-Cache': lambda v: 'Drupal',
                'X-Drupal-Dynamic-Cache': lambda v: 'Drupal',
            }
            
            for header, extractor in tech_signatures.items():
                if header in headers:
                    tech = extractor(headers[header])
                    if tech:
                        technologies.append({'type': 'header', 'name': tech, 'source': header})
            
            # Check HTML meta tags
            soup = BeautifulSoup(response.text, 'html.parser')
            generator = soup.find('meta', {'name': 'generator'})
            if generator:
                technologies.append({'type': 'meta', 'name': generator.get('content', ''), 'source': 'meta'})
            
            # Check for common frameworks
            if 'wp-content' in response.text:
                technologies.append({'type': 'detected', 'name': 'WordPress', 'source': 'content'})
            if 'jquery' in response.text.lower():
                technologies.append({'type': 'detected', 'name': 'jQuery', 'source': 'content'})
            if 'react' in response.text.lower():
                technologies.append({'type': 'detected', 'name': 'React', 'source': 'content'})
            
            self.results['technologies'] = technologies
            self.results['headers'] = dict(headers)
            Logger.success(f"Detected {len(technologies)} technologies")
        except Exception as e:
            Logger.error(f"Technology detection failed: {e}")
        
        return self.results['technologies']
    
    async def crawl_target(self, max_urls: int = 100):
        """Crawl the target for endpoints and JS files"""
        Logger.info(f"Crawling target (max {max_urls} URLs)...")
        target_url = self.normalize_target()
        visited = set()
        to_visit = [target_url]
        endpoints = set()
        js_files = set()
        
        async with aiohttp.ClientSession() as session:
            while to_visit and len(visited) < max_urls:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                
                try:
                    async with session.get(url, timeout=10, ssl=False) as response:
                        if response.status == 200:
                            visited.add(url)
                            endpoints.add(url)
                            
                            text = await response.text()
                            soup = BeautifulSoup(text, 'html.parser')
                            
                            # Extract links
                            for link in soup.find_all('a', href=True):
                                full_url = urljoin(url, link['href'])
                                if urlparse(full_url).netloc == urlparse(target_url).netloc:
                                    if full_url not in visited and len(visited) < max_urls:
                                        to_visit.append(full_url)
                            
                            # Extract JavaScript files
                            for script in soup.find_all('script', src=True):
                                js_url = urljoin(url, script['src'])
                                js_files.add(js_url)
                            
                            # Extract forms
                            forms = soup.find_all('form')
                            for form in forms:
                                action = form.get('action', '')
                                method = form.get('method', 'GET').upper()
                                inputs = form.find_all('input')
                                form_data = {
                                    'url': url,
                                    'action': urljoin(url, action),
                                    'method': method,
                                    'inputs': []
                                }
                                for input_field in inputs:
                                    form_data['inputs'].append({
                                        'name': input_field.get('name', ''),
                                        'type': input_field.get('type', 'text'),
                                        'value': input_field.get('value', '')
                                    })
                                self.results['forms'].append(form_data)
                            
                            # Extract URL parameters
                            parsed = urlparse(url)
                            if parsed.query:
                                params = parse_qs(parsed.query)
                                for param in params.keys():
                                    self.results['parameters'].add(param)
                
                except Exception as e:
                    Logger.warning(f"Failed to crawl {url}: {e}")
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        self.results['endpoints'] = list(endpoints)
        self.results['js_files'] = list(js_files)
        Logger.success(f"Crawled {len(endpoints)} endpoints and found {len(js_files)} JS files")
        return endpoints, js_files

class VulnerabilityScanner:
    """Handles vulnerability scanning using Nikto and Nuclei"""
    
    def __init__(self, target: str, output_dir: str = "scan_results"):
        self.target = target
        self.output_dir = output_dir
        self.results = {
            'nikto': [],
            'nuclei': [],
            'custom': []
        }
        
        # Create output directory
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def run_nikto(self) -> List[Dict]:
        """Run Nikto scanner"""
        Logger.info("Running Nikto vulnerability scanner...")
        
        try:
            # Check if nikto is installed
            if not self._check_tool_exists('nikto'):
                Logger.error("Nikto is not installed. Skipping Nikto scan.")
                return []
            
            output_file = os.path.join(self.output_dir, f"nikto_{int(time.time())}.txt")
            
            # Run Nikto
            cmd = [
                'nikto',
                '-h', self.target,
                '-Format', 'json',
                '-output', output_file,
                '-Tuning', '1234567890abcde'  # All checks
            ]
            
            Logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse Nikto output
            vulnerabilities = self._parse_nikto_output(result.stdout)
            self.results['nikto'] = vulnerabilities
            
            Logger.success(f"Nikto found {len(vulnerabilities)} potential issues")
            return vulnerabilities
            
        except subprocess.TimeoutExpired:
            Logger.error("Nikto scan timed out")
            return []
        except Exception as e:
            Logger.error(f"Nikto scan failed: {e}")
            return []
    
    def run_nuclei(self, templates: List[str] = None) -> List[Dict]:
        """Run Nuclei scanner"""
        Logger.info("Running Nuclei vulnerability scanner...")
        
        try:
            # Check if nuclei is installed
            if not self._check_tool_exists('nuclei'):
                Logger.error("Nuclei is not installed. Skipping Nuclei scan.")
                return []
            
            output_file = os.path.join(self.output_dir, f"nuclei_{int(time.time())}.json")
            
            cmd = [
                'nuclei',
                '-target', self.target,
                '-json-export', output_file,
                '-severity', 'low,medium,high,critical',
                '-stats'
            ]
            
            if templates:
                cmd.extend(['-t', ','.join(templates)])
            
            Logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse Nuclei output
            vulnerabilities = self._parse_nuclei_output(output_file)
            self.results['nuclei'] = vulnerabilities
            
            Logger.success(f"Nuclei found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except subprocess.TimeoutExpired:
            Logger.error("Nuclei scan timed out")
            return []
        except Exception as e:
            Logger.error(f"Nuclei scan failed: {e}")
            return []
    
    def custom_checks(self) -> List[Dict]:
        """Perform custom vulnerability checks"""
        Logger.info("Performing custom vulnerability checks...")
        vulnerabilities = []
        
        try:
            response = requests.get(self.target, timeout=10, verify=False)
            
            # Check for missing security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': None,
                'Referrer-Policy': None
            }
            
            missing_headers = []
            for header, expected in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'description': f'Missing security header: {header}',
                        'recommendation': f'Add {header} header to server configuration'
                    })
            
            # Check for information disclosure
            if 'Server' in response.headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'description': f'Server header reveals: {response.headers["Server"]}',
                    'recommendation': 'Remove or modify Server header'
                })
            
            # Check for directory listing
            test_paths = ['/images/', '/js/', '/css/', '/uploads/']
            for path in test_paths:
                try:
                    test_url = urljoin(self.target, path)
                    test_response = requests.get(test_url, timeout=5, verify=False)
                    if 'Index of' in test_response.text or 'Directory Listing' in test_response.text:
                        vulnerabilities.append({
                            'type': 'Directory Listing',
                            'severity': 'Medium',
                            'description': f'Directory listing enabled at {path}',
                            'recommendation': 'Disable directory listing in web server configuration'
                        })
                except:
                    pass
            
            # Check for common backup files
            backup_extensions = ['.bak', '.backup', '.old', '.swp', '~']
            for ext in backup_extensions:
                test_url = self.target + ext
                try:
                    test_response = requests.head(test_url, timeout=5, verify=False)
                    if test_response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Backup File Exposure',
                            'severity': 'High',
                            'description': f'Potential backup file found: {test_url}',
                            'recommendation': 'Remove backup files from web accessible directories'
                        })
                except:
                    pass
            
            self.results['custom'] = vulnerabilities
            Logger.success(f"Custom checks found {len(vulnerabilities)} issues")
            
        except Exception as e:
            Logger.error(f"Custom checks failed: {e}")
        
        return vulnerabilities
    
    def _parse_nikto_output(self, output: str) -> List[Dict]:
        """Parse Nikto output into structured format"""
        vulnerabilities = []
        
        for line in output.split('\n'):
            if '+ OSVDB-' in line or '+ ' in line:
                severity = 'Medium'
                if 'critical' in line.lower() or 'vulnerable' in line.lower():
                    severity = 'High'
                
                vulnerabilities.append({
                    'tool': 'Nikto',
                    'severity': severity,
                    'description': line.strip(),
                    'raw': line.strip()
                })
        
        return vulnerabilities
    
    def _parse_nuclei_output(self, output_file: str) -> List[Dict]:
        """Parse Nuclei JSON output"""
        vulnerabilities = []
        
        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                            vulnerabilities.append({
                                'tool': 'Nuclei',
                                'name': finding.get('info', {}).get('name', 'Unknown'),
                                'severity': finding.get('info', {}).get('severity', 'Unknown'),
                                'description': finding.get('info', {}).get('description', ''),
                                'url': finding.get('matched-at', ''),
                                'template': finding.get('template-id', ''),
                                'remediation': finding.get('info', {}).get('remediation', '')
                            })
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            Logger.error(f"Failed to parse Nuclei output: {e}")
        
        return vulnerabilities
    
    def _check_tool_exists(self, tool: str) -> bool:
        """Check if a tool is installed"""
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
            return True
        except:
            return False

class ReportGenerator:
    """Generates structured reports"""
    
    def __init__(self, recon_data: Dict, vuln_data: Dict):
        self.recon_data = recon_data
        self.vuln_data = vuln_data
    
    def generate_html_report(self, filename: str = "security_report.html"):
        """Generate HTML report"""
        Logger.info("Generating HTML report...")
        
        severity_counts = self._count_severities()
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {self.recon_data['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #333; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #4CAF50; background: #f9f9f9; }}
                .vulnerability {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #ff0000; }}
                .high {{ border-left: 5px solid #ff6600; }}
                .medium {{ border-left: 5px solid #ffcc00; }}
                .low {{ border-left: 5px solid #3399ff; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #4CAF50; color: white; }}
                .timestamp {{ color: #666; font-size: 0.9em; }}
                .severity-badge {{ padding: 3px 8px; border-radius: 3px; color: white; font-size: 0.8em; }}
                .critical-badge {{ background: #ff0000; }}
                .high-badge {{ background: #ff6600; }}
                .medium-badge {{ background: #ffcc00; color: black; }}
                .low-badge {{ background: #3399ff; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1> Security Assessment Report</h1>
                <p class="timestamp">Generated on: {self.recon_data.get('timestamp', datetime.now().isoformat())}</p>
                
                <div class="section">
                    <h2> Executive Summary</h2>
                    <p>Target: <strong>{self.recon_data['target']}</strong></p>
                    <p>Total Vulnerabilities Found: <strong>{sum(severity_counts.values())}</strong></p>
                    <ul>
                        <li><span class="severity-badge critical-badge">Critical</span>: {severity_counts.get('critical', 0)}</li>
                        <li><span class="severity-badge high-badge">High</span>: {severity_counts.get('high', 0)}</li>
                        <li><span class="severity-badge medium-badge">Medium</span>: {severity_counts.get('medium', 0)}</li>
                        <li><span class="severity-badge low-badge">Low</span>: {severity_counts.get('low', 0)}</li>
                    </ul>
                </div>
                
                <div class="section">
                    <h2>🔍 Reconnaissance Findings</h2>
                    <h3>DNS Information</h3>
                    <pre>{json.dumps(self.recon_data.get('dns', {}), indent=2)}</pre>
                    
                    <h3>Open Ports ({len(self.recon_data.get('ports', []))})</h3>
                    <table>
                        <tr><th>Port</th><th>Service</th></tr>
        """
        
        for port_info in self.recon_data.get('ports', []):
            html_content += f"<tr><td>{port_info['port']}</td><td>{port_info['service']}</td></tr>"
        
        html_content += """
                    </table>
                    
                    <h3>Technologies Detected</h3>
                    <table>
                        <tr><th>Technology</th><th>Source</th></tr>
        """
        
        for tech in self.recon_data.get('technologies', []):
            html_content += f"<tr><td>{tech.get('name', 'Unknown')}</td><td>{tech.get('source', 'Unknown')}</td></tr>"
        
        html_content += """
                    </table>
                </div>
                
                <div class="section">
                    <h2>🌐 Discovered Endpoints ({})</h2>
                    <ul>
        """.format(len(self.recon_data.get('endpoints', [])))
        
        for endpoint in list(self.recon_data.get('endpoints', []))[:20]:  # Limit to 20 for readability
            html_content += f"<li>{endpoint}</li>"
        
        html_content += """
                    </ul>
                </div>
                
                <div class="section">
                    <h2>🚨 Vulnerability Findings</h2>
        """
        
        # Combine all vulnerabilities
        all_vulns = []
        if isinstance(self.vuln_data, dict):
            all_vulns.extend(self.vuln_data.get('nikto', []))
            all_vulns.extend(self.vuln_data.get('nuclei', []))
            all_vulns.extend(self.vuln_data.get('custom', []))
        
        for vuln in all_vulns:
            severity = vuln.get('severity', 'Medium').lower()
            html_content += f"""
                    <div class="vulnerability {severity}">
                        <h3><span class="severity-badge {severity}-badge">{severity.upper()}</span> {vuln.get('type', vuln.get('name', 'Unknown'))}</h3>
                        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                        <p><strong>Recommendation:</strong> {vuln.get('recommendation', vuln.get('remediation', 'No recommendation available'))}</p>
                        <p><strong>Source:</strong> {vuln.get('tool', 'Custom Check')}</p>
                    </div>
            """
        
        html_content += """
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        Logger.success(f"HTML report generated: {filename}")
        return filename
    
    def generate_json_report(self, filename: str = "security_report.json"):
        """Generate JSON report"""
        Logger.info("Generating JSON report...")
        
        report = {
            'scan_info': {
                'target': self.recon_data['target'],
                'timestamp': self.recon_data.get('timestamp', datetime.now().isoformat()),
                'scan_duration': 'N/A'
            },
            'reconnaissance': self.recon_data,
            'vulnerabilities': self.vuln_data
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        Logger.success(f"JSON report generated: {filename}")
        return filename
    
    def _count_severities(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        all_vulns = []
        if isinstance(self.vuln_data, dict):
            all_vulns.extend(self.vuln_data.get('nikto', []))
            all_vulns.extend(self.vuln_data.get('nuclei', []))
            all_vulns.extend(self.vuln_data.get('custom', []))
        
        for vuln in all_vulns:
            severity = vuln.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts

class AutomatedScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, target: str, threads: int = 10, max_urls: int = 100):
        self.target = target
        self.threads = threads
        self.max_urls = max_urls
        self.recon = Reconnaissance(target, threads)
        self.vuln_scanner = VulnerabilityScanner(target)
        
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    async def run(self):
        """Run the complete scanning workflow"""
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"{Colors.BOLD}  Automated Reconnaissance & Vulnerability Scanner")
        print(f"{Colors.BOLD}{'='*60}\n")
        
        Logger.info(f"Starting scan on target: {self.target}")
        start_time = time.time()
        
        # Phase 1: Reconnaissance
        print(f"\n{Colors.BOLD}[Phase 1] Reconnaissance{Colors.RESET}")
        print("-" * 40)
        
        # DNS Enumeration
        self.recon.dns_enumeration()
        
        # Subdomain Enumeration
        self.recon.subdomain_enumeration()
        
        # Port Scanning
        self.recon.port_scanning()
        
        # Technology Detection
        self.recon.technology_detection()
        
        # Crawling
        await self.recon.crawl_target(self.max_urls)
        
        # Phase 2: Vulnerability Scanning
        print(f"\n{Colors.BOLD}[Phase 2] Vulnerability Scanning{Colors.RESET}")
        print("-" * 40)
        
        # Run custom checks first (fast)
        custom_vulns = self.vuln_scanner.custom_checks()
        
        # Run Nikto
        nikto_vulns = self.vuln_scanner.run_nikto()
        
        # Run Nuclei
        nuclei_vulns = self.vuln_scanner.run_nuclei()
        
        # Phase 3: Reporting
        print(f"\n{Colors.BOLD}[Phase 3] Report Generation{Colors.RESET}")
        print("-" * 40)
        
        report_gen = ReportGenerator(self.recon.results, self.vuln_scanner.results)
        
        # Generate reports
        report_gen.generate_html_report()
        report_gen.generate_json_report()
        
        # Display summary
        elapsed_time = time.time() - start_time
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"{Colors.BOLD}  Scan Complete")
        print(f"{Colors.BOLD}{'='*60}\n")
        
        Logger.success(f"Scan completed in {elapsed_time:.2f} seconds")
        Logger.info(f"Endpoints discovered: {len(self.recon.results['endpoints'])}")
        Logger.info(f"JavaScript files found: {len(self.recon.results['js_files'])}")
        
        total_vulns = len(custom_vulns) + len(nikto_vulns) + len(nuclei_vulns)
        Logger.info(f"Total vulnerabilities found: {total_vulns}")
        
        if total_vulns > 0:
            Logger.warning(f"Review the HTML report for detailed findings")
        
        return {
            'recon': self.recon.results,
            'vulnerabilities': self.vuln_scanner.results,
            'scan_time': elapsed_time
        }

def main():
    parser = argparse.ArgumentParser(
        description='Automated Reconnaissance & Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py https://example.com
  python scanner.py example.com --threads 20 --max-urls 200
  python scanner.py 192.168.1.1 --ports 80,443,8080
        """
    )
    
    parser.add_argument('target', help='Target domain, URL, or IP address')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--max-urls', type=int, default=100, help='Maximum URLs to crawl (default: 100)')
    parser.add_argument('--ports', help='Comma-separated ports to scan (default: common ports)')
    parser.add_argument('--skip-nikto', action='store_true', help='Skip Nikto scan')
    parser.add_argument('--skip-nuclei', action='store_true', help='Skip Nuclei scan')
    parser.add_argument('--skip-crawl', action='store_true', help='Skip crawling')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        Logger.error("Target is required")
        sys.exit(1)
    
    # Run scanner
    scanner = AutomatedScanner(args.target, args.threads, args.max_urls)
    
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        Logger.warning("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        Logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
