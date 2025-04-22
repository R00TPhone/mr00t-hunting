#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MR00T TERMINAL HUNTER v4.0 - Complete Bug Bounty Suite
"""

import os
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ==================== MR00T CONFIGURATION ====================
class MR00TConfig:
    # Tool Paths (Auto-detected)
    TOOLS = {
        'subfinder': '/usr/bin/subfinder',
        'nuclei': '/usr/bin/nuclei',
        'httpx': '/usr/bin/httpx',
        'waybackurls': '/usr/bin/waybackurls',
        'sqlmap': '/usr/bin/sqlmap'
    }
    
    # Wordlists
    WORDLISTS = {
        'subdomains': '/usr/share/wordlists/subdomains.txt',
        'directories': '/usr/share/wordlists/dirbuster.txt'
    }
    
    # API Keys
    APIS = {
        'virustotal': os.getenv('VT_API_KEY', ''),
        'shodan': os.getenv('SHODAN_API_KEY', '')
    }

# ==================== MR00T THEME ====================
class MR00TTheme:
    BANNER = r"""
    \033[1;32m
    ███╗   ███╗██████╗ ██████╗ ██████╗ ████████╗   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ████╗ ████║██╔══██╗╚════██╗██╔══██╗╚══██╔══╝   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██╔████╔██║██████╔╝ █████╔╝██████╔╝   ██║█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║╚██╔╝██║██╔══██╗██╔═══╝ ██╔══██╗   ██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║ ╚═╝ ██║██║  ██║███████╗██║  ██║   ██║      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    \033[0m
    """
    
    COLORS = {
        'critical': '\033[1;31m',
        'high': '\033[1;33m',
        'medium': '\033[1;36m',
        'low': '\033[1;37m',
        'info': '\033[1;34m',
        'debug': '\033[1;35m',
        'reset': '\033[0m'
    }

# ==================== CORE SCANNER CLASS ====================
class MR00TScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'start_time': datetime.now().isoformat(),
            'end_time': '',
            'stats': {
                'subdomains': 0,
                'urls': 0,
                'vulnerabilities': 0
            },
            'subdomains': [],
            'urls': [],
            'vulnerabilities': []
        }
        
        # Validate target format
        if not self._validate_target():
            print(f"{MR00TTheme.COLORS['critical']}[!] Invalid target format{MR00TTheme.COLORS['reset']}")
            sys.exit(1)
            
        # Check tool dependencies
        self._check_dependencies()
    
    def _validate_target(self):
        """Validate target format"""
        try:
            if '.' not in self.target:
                return False
                
            if not (self.target.startswith('http://') or self.target.startswith('https://')):
                self.target = f'http://{self.target}'
                
            urlparse(self.target)
            return True
        except:
            return False
    
    def _check_dependencies(self):
        """Check required tools"""
        missing = []
        for tool, path in MR00TConfig.TOOLS.items():
            if not os.path.exists(path):
                missing.append(tool)
        
        if missing:
            print(f"{MR00TTheme.COLORS['high']}[!] Missing tools: {', '.join(missing)}{MR00TTheme.COLORS['reset']}")
            sys.exit(1)
    
    def _run_command(self, cmd):
        """Execute shell command"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"{MR00TTheme.COLORS['debug']}[DEBUG] Command failed: {cmd}{MR00TTheme.COLORS['reset']}")
            return None
    
    # ==================== RECON MODULES ====================
    def find_subdomains(self):
        """Discover subdomains using multiple techniques"""
        print(f"\n{MR00TTheme.COLORS['info']}[*] Running subdomain discovery{MR00TTheme.COLORS['reset']}")
        
        methods = [
            self._subfinder_scan,
            self._crt_sh_scan,
            self._assetfinder_scan
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(method) for method in methods]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['subdomains'].extend(result)
                    self.results['stats']['subdomains'] = len(self.results['subdomains'])
                    print(f"  {MR00TTheme.COLORS['info']}→ Found {len(result)} new subdomains (Total: {self.results['stats']['subdomains']}){MR00TTheme.COLORS['reset']}")
    
    def _subfinder_scan(self):
        """Use subfinder for subdomain enumeration"""
        cmd = f"{MR00TConfig.TOOLS['subfinder']} -d {self.target} -silent"
        output = self._run_command(cmd)
        return list(set(output.split('\n'))) if output else []
    
    def _crt_sh_scan(self):
        """Check crt.sh certificates"""
        domain = urlparse(self.target).netloc
        cmd = f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*//g' | sort -u"
        output = self._run_command(cmd)
        return list(set(output.split('\n'))) if output else []
    
    def _assetfinder_scan(self):
        """Use assetfinder (fallback)"""
        cmd = f"assetfinder --subs-only {self.target}"
        output = self._run_command(cmd)
        return list(set(output.split('\n'))) if output else []
    
    def find_urls(self):
        """Discover URLs using multiple sources"""
        print(f"\n{MR00TTheme.COLORS['info']}[*] Harvesting URLs{MR00TTheme.COLORS['reset']}")
        
        methods = [
            self._waybackurls_scan,
            self._gau_scan,
            self._dirsearch_scan
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(method) for method in methods]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['urls'].extend(result)
                    self.results['stats']['urls'] = len(self.results['urls'])
                    print(f"  {MR00TTheme.COLORS['info']}→ Found {len(result)} new URLs (Total: {self.results['stats']['urls']}){MR00TTheme.COLORS['reset']}")
    
    def _waybackurls_scan(self):
        """Use waybackurls"""
        domain = urlparse(self.target).netloc
        cmd = f"{MR00TConfig.TOOLS['waybackurls']} {domain}"
        output = self._run_command(cmd)
        return list(set(output.split('\n'))) if output else []
    
    def _gau_scan(self):
        """Use gau (fallback)"""
        cmd = f"gau {self.target}"
        output = self._run_command(cmd)
        return list(set(output.split('\n'))) if output else []
    
    def _dirsearch_scan(self):
        """Basic directory brute-forcing"""
        cmd = f"dirsearch -u {self.target} -w {MR00TConfig.WORDLISTS['directories']} --quiet -o /tmp/dirsearch.txt"
        self._run_command(cmd)
        
        if os.path.exists('/tmp/dirsearch.txt'):
            with open('/tmp/dirsearch.txt', 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        return []
    
    # ==================== VULNERABILITY SCANNING ====================
    def scan_vulnerabilities(self):
        """Run comprehensive vulnerability scanning"""
        print(f"\n{MR00TTheme.COLORS['info']}[*] Scanning for vulnerabilities{MR00TTheme.COLORS['reset']}")
        
        scan_methods = [
            self._nuclei_scan,
            self._sqlmap_scan,
            self._xss_scan,
            self._ssrf_scan
        ]
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(method) for method in scan_methods]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['vulnerabilities'].extend(result)
                    self.results['stats']['vulnerabilities'] = len(self.results['vulnerabilities'])
                    print(f"  {MR00TTheme.COLORS['info']}→ Found {len(result)} new vulnerabilities (Total: {self.results['stats']['vulnerabilities']}){MR00TTheme.COLORS['reset']}")
    
    def _nuclei_scan(self):
        """Run nuclei scan"""
        cmd = f"{MR00TConfig.TOOLS['nuclei']} -u {self.target} -severity critical,high -silent -json"
        output = self._run_command(cmd)
        
        if not output:
            return []
            
        vulns = []
        for line in output.split('\n'):
            try:
                data = json.loads(line)
                vulns.append({
                    'type': data.get('templateID', 'unknown'),
                    'url': data.get('host', ''),
                    'severity': data.get('severity', 'medium'),
                    'description': data.get('info', {}).get('description', ''),
                    'curl_command': f"curl -X {data.get('request', 'GET')} '{data.get('host', '')}'"
                })
            except:
                continue
                
        return vulns
    
    def _sqlmap_scan(self):
        """Run basic SQLi checks"""
        print(f"  {MR00TTheme.COLORS['debug']}[*] Running SQLi checks (this may take a while){MR00TTheme.COLORS['reset']}")
        cmd = f"{MR00TConfig.TOOLS['sqlmap']} -u {self.target} --batch --crawl=1 --level=2 --risk=2 --output-dir=/tmp/sqlmap"
        self._run_command(cmd)
        
        report_file = "/tmp/sqlmap/*/log"
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                content = f.read()
                if "sqlmap identified the following injection point" in content:
                    return [{
                        'type': 'SQL Injection',
                        'url': self.target,
                        'severity': 'critical',
                        'description': 'SQL injection vulnerability detected',
                        'curl_command': f"curl '{self.target}'"
                    }]
        return []
    
    def _xss_scan(self):
        """Run basic XSS checks"""
        print(f"  {MR00TTheme.COLORS['debug']}[*] Running XSS checks{MR00TTheme.COLORS['reset']}")
        test_payload = "<script>alert('MR00T_XSS')</script>"
        cmd = f"{MR00TConfig.TOOLS['httpx']} -u {self.target}/?test={test_payload} -silent -status-code -content-length"
        output = self._run_command(cmd)
        
        if output and test_payload in output:
            return [{
                'type': 'Reflected XSS',
                'url': f"{self.target}/?test={test_payload}",
                'severity': 'high',
                'description': 'Reflected XSS vulnerability detected',
                'curl_command': f"curl '{self.target}/?test={test_payload}'"
            }]
        return []
    
    def _ssrf_scan(self):
        """Run basic SSRF checks"""
        print(f"  {MR00TTheme.COLORS['debug']}[*] Running SSRF checks{MR00TTheme.COLORS['reset']}")
        test_url = "http://169.254.169.254/latest/meta-data/"
        cmd = f"{MR00TConfig.TOOLS['httpx']} -u {self.target}/?url={test_url} -silent -status-code"
        output = self._run_command(cmd)
        
        if output and "200" in output:
            return [{
                'type': 'Potential SSRF',
                'url': f"{self.target}/?url={test_url}",
                'severity': 'high',
                'description': 'Possible SSRF vulnerability detected',
                'curl_command': f"curl '{self.target}/?url={test_url}'"
            }]
        return []
    
    # ==================== REPORTING ====================
    def generate_report(self, report_format='txt'):
        """Generate comprehensive report"""
        self.results['end_time'] = datetime.now().isoformat()
        
        if report_format == 'txt':
            self._generate_txt_report()
        elif report_format == 'json':
            self._generate_json_report()
        elif report_format == 'pdf':
            self._generate_pdf_report()
        elif report_format == 'html':
            self._generate_html_report()
        else:
            print(f"{MR00TTheme.COLORS['high']}[!] Invalid report format{MR00TTheme.COLORS['reset']}")
    
    def _generate_txt_report(self):
        """Generate text report"""
        filename = f"mr00t_report_{self.target.replace('://', '_').replace('/', '_')}.txt"
        
        report = f"""
MR00T SECURITY REPORT
=====================
Target: {self.results['target']}
Start Time: {self.results['start_time']}
End Time: {self.results['end_time']}

=== STATISTICS ===
Subdomains Found: {self.results['stats']['subdomains']}
URLs Collected: {self.results['stats']['urls']}
Vulnerabilities Found: {self.results['stats']['vulnerabilities']}

=== SUBDOMAINS ===
{'\n'.join(self.results['subdomains'][:20])}
... (showing 20 of {len(self.results['subdomains'])})

=== TOP VULNERABILITIES ===
"""
        for vuln in sorted(
            self.results['vulnerabilities'],
            key=lambda x: {'critical':3, 'high':2, 'medium':1, 'low':0}[x['severity']],
            reverse=True
        )[:10]:
            color = MR00TTheme.COLORS[vuln['severity']]
            report += f"""
[{vuln['severity'].upper()}] {color}{vuln['type']}{MR00TTheme.COLORS['reset']}
URL: {vuln['url']}
Description: {vuln.get('description', 'N/A')}
CURL: {vuln.get('curl_command', 'N/A')}
"""
        
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"\n{MR00TTheme.COLORS['info']}[+] TXT report saved to {filename}{MR00TTheme.COLORS['reset']}")
    
    def _generate_json_report(self):
        """Generate JSON report"""
        filename = f"mr00t_report_{self.target.replace('://', '_').replace('/', '_')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n{MR00TTheme.COLORS['info']}[+] JSON report saved to {filename}{MR00TTheme.COLORS['reset']}")
    
    def _generate_pdf_report(self):
        """Generate PDF report"""
        try:
            from fpdf import FPDF
        except ImportError:
            print(f"{MR00TTheme.COLORS['high']}[!] Install fpdf with: pip install fpdf{MR00TTheme.COLORS['reset']}")
            return
            
        filename = f"mr00t_report_{self.target.replace('://', '_').replace('/', '_')}.pdf"
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        
        # Header
        pdf.cell(0, 10, "MR00T SECURITY REPORT", 0, 1, 'C')
        pdf.set_font("Arial", size=12)
        
        # Metadata
        pdf.cell(0, 10, f"Target: {self.results['target']}", 0, 1)
        pdf.cell(0, 10, f"Scan Period: {self.results['start_time']} to {self.results['end_time']}", 0, 1)
        pdf.ln(5)
        
        # Statistics
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, "Scan Statistics", 0, 1)
        pdf.set_font("Arial", size=12)
        
        pdf.cell(0, 10, f"Subdomains Found: {self.results['stats']['subdomains']}", 0, 1)
        pdf.cell(0, 10, f"URLs Collected: {self.results['stats']['urls']}", 0, 1)
        pdf.cell(0, 10, f"Vulnerabilities Found: {self.results['stats']['vulnerabilities']}", 0, 1)
        pdf.ln(10)
        
        # Vulnerabilities
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, "Critical Findings", 0, 1)
        pdf.set_font("Arial", size=10)
        
        for vuln in sorted(
            self.results['vulnerabilities'],
            key=lambda x: {'critical':3, 'high':2, 'medium':1, 'low':0}[x['severity']],
            reverse=True
        )[:10]:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, f"[{vuln['severity'].upper()}] {vuln['type']}", 0, 1)
            pdf.set_font("Arial", size=10)
            
            pdf.multi_cell(0, 5, f"URL: {vuln['url']}")
            pdf.multi_cell(0, 5, f"Description: {vuln.get('description', 'N/A')}")
            pdf.multi_cell(0, 5, f"CURL Command: {vuln.get('curl_command', 'N/A')}")
            pdf.ln(5)
        
        pdf.output(filename)
        print(f"\n{MR00TTheme.COLORS['info']}[+] PDF report saved to {filename}{MR00TTheme.COLORS['reset']}")
    
    def _generate_html_report(self):
        """Generate HTML report"""
        filename = f"mr00t_report_{self.target.replace('://', '_').replace('/', '_')}.html"
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MR00T Security Report - {self.results['target']}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background-color: #0a0a0a; color: #00ff00; }}
        .header {{ text-align: center; margin-bottom: 20px; }}
        .critical {{ color: #ff0000; }}
        .high {{ color: #ff6600; }}
        .medium {{ color: #00ffff; }}
        .low {{ color: #ffffff; }}
        .vuln {{ margin-bottom: 15px; border-left: 3px solid; padding-left: 10px; }}
        pre {{ background-color: #1a1a1a; padding: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MR00T SECURITY REPORT</h1>
        <h2>Target: {self.results['target']}</h2>
        <p>Scan Period: {self.results['start_time']} to {self.results['end_time']}</p>
    </div>
    
    <div class="stats">
        <h3>Scan Statistics</h3>
        <ul>
            <li>Subdomains Found: {self.results['stats']['subdomains']}</li>
            <li>URLs Collected: {self.results['stats']['urls']}</li>
            <li>Vulnerabilities Found: {self.results['stats']['vulnerabilities']}</li>
        </ul>
    </div>
    
    <div class="findings">
        <h3>Critical Findings</h3>
"""
        for vuln in sorted(
            self.results['vulnerabilities'],
            key=lambda x: {'critical':3, 'high':2, 'medium':1, 'low':0}[x['severity']],
            reverse=True
        )[:10]:
            html += f"""
        <div class="vuln {vuln['severity']}">
            <h4>[{vuln['severity'].upper()}] {vuln['type']}</h4>
            <p><strong>URL:</strong> {vuln['url']}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
            <pre>{vuln.get('curl_command', 'N/A')}</pre>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        with open(filename, 'w') as f:
            f.write(html)
        
        print(f"\n{MR00TTheme.COLORS['info']}[+] HTML report saved to {filename}{MR00TTheme.COLORS['reset']}")

# ==================== MAIN FUNCTION ====================
def main():
    parser = argparse.ArgumentParser(
        description="MR00T Terminal Hunter - Complete Bug Bounty Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=MR00TTheme.BANNER + """
Examples:
  ./mr00t.py example.com --full --report pdf
  ./mr00t.py https://example.com --recon --report json
  ./mr00t.py api.example.com --vuln --report html
"""
    )
    
    parser.add_argument('target', help="Target domain or URL")
    parser.add_argument('--recon', action='store_true', help="Run reconnaissance only")
    parser.add_argument('--vuln', action='store_true', help="Run vulnerability scanning only")
    parser.add_argument('--full', action='store_true', help="Run complete assessment (recon + vuln)")
    parser.add_argument('--report', choices=['txt', 'json', 'pdf', 'html'], default='txt', help="Report format")
    parser.add_argument('--quiet', action='store_true', help="Suppress banner output")
    
    args = parser.parse_args()
    
    if not args.quiet:
        print(MR00TTheme.BANNER)
    
    scanner = MR00TScanner(args.target)
    
    if args.recon:
        scanner.find_subdomains()
        scanner.find_urls()
    elif args.vuln:
        scanner.scan_vulnerabilities()
    elif args.full:
        scanner.find_subdomains()
        scanner.find_urls()
        scanner.scan_vulnerabilities()
    else:
        print(f"{MR00TTheme.COLORS['high']}[!] Please specify scan type (--recon, --vuln, or --full){MR00TTheme.COLORS['reset']}")
        sys.exit(1)
    
    scanner.generate_report(args.report)

if __name__ == "__main__":
    main()
