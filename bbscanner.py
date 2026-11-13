#!/usr/bin/env python3
"""
Security Recon Scanner v1.0
Automated reconnaissance and vulnerability discovery framework
Author: e4zyy | NOEL BUNSIAU
Modified: Removed payout estimates, improved structure
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set


# ═════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════

@dataclass
class Config:
    threads: int = 20
    timeout: int = 10
    nuclei_rate_limit: int = 100
    nuclei_templates: str = ""
    output_dir: str = "recon_results"
    wordlist: str = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    resolvers: str = "/usr/share/wordlists/seclists/Miscellaneous/dns-resolvers.txt"
    debug: bool = False


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'


# ═════════════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ═════════════════════════════════════════════════════════════════════

class ReconScanner:
    def __init__(self, config: Config):
        self.config = config
        self.targets: List[str] = []
        self.results: Dict = {}
        self.vulnerabilities: List[Dict] = []
        self.setup_logging()
        self.setup_directories()

    def setup_logging(self):
        """Configure logging with debug support"""
        level = logging.DEBUG if self.config.debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(f"{self.config.output_dir}/scanner.log")
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_directories(self):
        """Create output directory structure"""
        dirs = [
            self.config.output_dir,
            f"{self.config.output_dir}/subdomains",
            f"{self.config.output_dir}/alive",
            f"{self.config.output_dir}/nuclei",
            f"{self.config.output_dir}/urls",
            f"{self.config.output_dir}/ports",
            f"{self.config.output_dir}/vulns",
            f"{self.config.output_dir}/reports",
            f"{self.config.output_dir}/tech",
            f"{self.config.output_dir}/js",
            f"{self.config.output_dir}/endpoints"
        ]
        for d in dirs:
            Path(d).mkdir(parents=True, exist_ok=True)

    def print_banner(self):
        """Display scanner banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║           SECURITY RECON SCANNER v3.0                             ║
║     Automated reconnaissance and vulnerability discovery          ║
╠══════════════════════════════════════════════════════════════════╣
║  Tools: Subfinder | Httpx | Nuclei | Naabu | Waybackurls | Gau    ║
║         Dalfox | Katana | FFUF | Arjun                            ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)

    def load_targets(self, file_path: str):
        """Load target domains from file"""
        self.logger.info(f"Loading targets from {file_path}")
        try:
            with open(file_path, 'r') as f:
                self.targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(self.targets)} targets")
            self.logger.debug(f"Targets: {self.targets}")
        except Exception as e:
            self.logger.error(f"Failed to load targets: {e}")
            sys.exit(1)

    def run_command(self, cmd: str, output_file: Optional[str] = None,
                    timeout: int = 300, shell: bool = True) -> str:
        """Execute shell command with error handling"""
        self.logger.debug(f"Running: {cmd}")
        try:
            result = subprocess.run(
                cmd, shell=shell, capture_output=True, text=True,
                timeout=timeout, executable='/bin/bash'
            )

            output = result.stdout + result.stderr

            if output_file and result.stdout:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)

            if result.returncode != 0 and self.config.debug:
                self.logger.debug(f"Command stderr: {result.stderr}")

            return result.stdout

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out: {cmd[:50]}...")
            return ""
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            return ""

    # ═════════════════════════════════════════════════════════════════
    # PHASE 1: SUBDOMAIN ENUMERATION
    # ═════════════════════════════════════════════════════════════════

    def run_subfinder(self, domain: str) -> Set[str]:
        """Enumerate subdomains using subfinder"""
        self.logger.info(f"[{domain}] Running subfinder...")
        output_file = f"{self.config.output_dir}/subdomains/{domain}_subfinder.txt"

        commands = [
            f"subfinder -d {domain} -all -recursive -o {output_file} -silent",
            f"subfinder -d {domain} -o {output_file} -silent -t {self.config.threads}",
        ]

        for cmd in commands:
            self.run_command(cmd, timeout=180)

        subdomains = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = {line.strip() for line in f if line.strip()}

        self.logger.info(f"[{domain}] Found {len(subdomains)} subdomains")
        return subdomains

    def run_amass(self, domain: str) -> Set[str]:
        """Passive enumeration with amass"""
        self.logger.info(f"[{domain}] Running amass...")
        output_file = f"{self.config.output_dir}/subdomains/{domain}_amass.txt"

        cmd = f"amass enum -passive -d {domain} -o {output_file} -timeout 5"
        self.run_command(cmd, timeout=300)

        subdomains = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = {line.strip() for line in f if line.strip()}
        return subdomains

    def run_assetfinder(self, domain: str) -> Set[str]:
        """Fast subdomain discovery"""
        self.logger.info(f"[{domain}] Running assetfinder...")
        output_file = f"{self.config.output_dir}/subdomains/{domain}_assetfinder.txt"

        cmd = f"assetfinder --subs-only {domain} | tee {output_file}"
        self.run_command(cmd, timeout=120)

        subdomains = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = {line.strip() for line in f if line.strip()}
        return subdomains

    def merge_subdomains(self, domain: str, subdomain_sets: List[Set[str]]) -> List[str]:
        """Merge and deduplicate subdomains"""
        all_subs = set().union(*subdomain_sets)

        filtered = set()
        for sub in all_subs:
            if domain in sub and '*' not in sub:
                filtered.add(sub.lower())

        output_file = f"{self.config.output_dir}/subdomains/{domain}_all.txt"
        with open(output_file, 'w') as f:
            f.write('\n'.join(sorted(filtered)))

        self.logger.info(f"[{domain}] Total unique subdomains: {len(filtered)}")
        return list(filtered)

    # ═════════════════════════════════════════════════════════════════
    # PHASE 2: HTTP PROBING & TECH DETECTION
    # ═════════════════════════════════════════════════════════════════

    def run_httpx(self, domain: str, subdomains: List[str]) -> List[str]:
        """Fast HTTP probing with httpx"""
        self.logger.info(f"[{domain}] Running httpx...")

        input_file = f"{self.config.output_dir}/subdomains/{domain}_all.txt"
        output_file = f"{self.config.output_dir}/alive/{domain}_httpx.json"

        with open(input_file, 'w') as f:
            f.write('\n'.join(subdomains))

        cmd = (f"httpx -l {input_file} -o {output_file} "
               f"-json -title -tech -status-code -web-server -follow-redirects "
               f"-threads {self.config.threads} -timeout {self.config.timeout}")

        self.run_command(cmd, timeout=300)

        alive_urls = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        alive_urls.append(data.get('url', ''))
                        self.results[data.get('url', '')] = data
                    except:
                        pass

        self.logger.info(f"[{domain}] Alive hosts: {len(alive_urls)}")
        return alive_urls

    def run_naabu(self, domain: str) -> List[Dict]:
        """Port scanning with naabu"""
        self.logger.info(f"[{domain}] Running naabu port scan...")

        input_file = f"{self.config.output_dir}/subdomains/{domain}_all.txt"
        output_file = f"{self.config.output_dir}/ports/{domain}_ports.txt"

        cmd = (f"naabu -list {input_file} -top-ports 1000 "
               f"-o {output_file} -rate 1000 -silent")

        self.run_command(cmd, timeout=600)

        ports = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        host, port = line.strip().rsplit(':', 1)
                        ports.append({'host': host, 'port': int(port)})

        return ports

    # ═════════════════════════════════════════════════════════════════
    # PHASE 3: URL COLLECTION
    # ═════════════════════════════════════════════════════════════════

    def run_waybackurls(self, domain: str) -> Set[str]:
        """Collect URLs from Wayback Machine"""
        self.logger.info(f"[{domain}] Collecting wayback URLs...")
        output_file = f"{self.config.output_dir}/urls/{domain}_wayback.txt"

        cmd = f"echo {domain} | waybackurls | anew {output_file}"
        self.run_command(cmd, timeout=180)

        urls = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                urls = {line.strip() for line in f if line.strip()}
        return urls

    def run_gau(self, domain: str) -> Set[str]:
        """GetAllUrls - alternative to waybackurls"""
        self.logger.info(f"[{domain}] Running gau...")
        output_file = f"{self.config.output_dir}/urls/{domain}_gau.txt"

        cmd = f"gau {domain} --o {output_file} --threads {self.config.threads}"
        self.run_command(cmd, timeout=300)

        urls = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                urls = {line.strip() for line in f if line.strip()}
        return urls

    def run_katana(self, domain: str, alive_urls: List[str]) -> Set[str]:
        """Crawl live sites with katana"""
        self.logger.info(f"[{domain}] Crawling with katana...")
        output_file = f"{self.config.output_dir}/urls/{domain}_katana.txt"

        input_file = f"{self.config.output_dir}/urls/{domain}_alive_input.txt"
        with open(input_file, 'w') as f:
            f.write('\n'.join(alive_urls))

        cmd = f"katana -list {input_file} -o {output_file} -d 3 -silent -jc -kf all"
        self.run_command(cmd, timeout=300)

        urls = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                urls = {line.strip() for line in f if line.strip()}
        return urls

    def filter_interesting_urls(self, domain: str, all_urls: Set[str]) -> Dict[str, List[str]]:
        """Filter URLs by type for targeted testing"""
        self.logger.info(f"[{domain}] Filtering interesting URLs...")

        patterns = {
            'js_files': r'\.js$',
            'api_endpoints': r'(/api/|/v1/|/v2/|/graphql|/rest/|/swagger|/docs)',
            'admin_panels': r'(/admin|/login|/signin|/dashboard|/panel|/manage)',
            'upload_points': r'(/upload|/file|/import|/attachment)',
            'redirects': r'[?&](redirect|url|next|return|callback|goto)=',
            'params': r'\?.*=',
            'sensitive': r'(\.env|\.git|\.svn|\.htaccess|config\.|backup|\.sql)',
            'ssrf_candidates': r'[?&](url|path|dest|uri|location|site|data)=http'
        }

        categorized = {k: [] for k in patterns.keys()}

        for url in all_urls:
            for category, pattern in patterns.items():
                if re.search(pattern, url, re.IGNORECASE):
                    categorized[category].append(url)

        for category, urls in categorized.items():
            if urls:
                output_file = f"{self.config.output_dir}/urls/{domain}_{category}.txt"
                with open(output_file, 'w') as f:
                    f.write('\n'.join(sorted(set(urls))))
                self.logger.info(f"[{domain}] {category}: {len(urls)}")

        return categorized

    # ═════════════════════════════════════════════════════════════════
    # PHASE 4: VULNERABILITY SCANNING
    # ═════════════════════════════════════════════════════════════════

    def run_nuclei(self, domain: str, targets: List[str], templates: str = "") -> List[Dict]:
        """Nuclei vulnerability scanner"""
        self.logger.info(f"[{domain}] Running Nuclei scan...")

        input_file = f"{self.config.output_dir}/nuclei/{domain}_input.txt"
        output_file = f"{self.config.output_dir}/nuclei/{domain}_results.json"

        with open(input_file, 'w') as f:
            f.write('\n'.join(targets))

        severity_filter = "critical,high,medium"

        template_args = ""
        if templates:
            template_args = f"-t {templates}"
        else:
            template_args = ("-t ~/nuclei-templates/http/ "
                           "-t ~/nuclei-templates/cves/ "
                           "-t ~/nuclei-templates/vulnerabilities/ "
                           "-t ~/nuclei-templates/exposures/")

        cmd = (f"nuclei -l {input_file} -o {output_file} "
               f"-s {severity_filter} {template_args} "
               f"-rate-limit {self.config.nuclei_rate_limit} "
               f"-timeout 10 -retries 1 -stats -silent -json")

        self.run_command(cmd, timeout=1800)

        vulns = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        vulns.append(data)
                        self.vulnerabilities.append({
                            'domain': domain,
                            'timestamp': datetime.now().isoformat(),
                            'template': data.get('template-id', ''),
                            'name': data.get('info', {}).get('name', ''),
                            'severity': data.get('info', {}).get('severity', ''),
                            'host': data.get('host', ''),
                            'matched': data.get('matched-at', ''),
                            'extracted': data.get('extracted-results', [])
                        })
                    except:
                        pass

        self.logger.info(f"[{domain}] Nuclei found {len(vulns)} potential findings")
        return vulns

    def run_dalfox(self, domain: str, urls: List[str]) -> List[Dict]:
        """XSS scanning with dalfox"""
        self.logger.info(f"[{domain}] Running Dalfox XSS scan...")

        param_urls = [u for u in urls if '?' in u or '=' in u]
        if not param_urls:
            return []

        input_file = f"{self.config.output_dir}/urls/{domain}_xss_input.txt"
        output_file = f"{self.config.output_dir}/vulns/{domain}_xss.json"

        with open(input_file, 'w') as f:
            f.write('\n'.join(param_urls[:1000]))

        cmd = (f"dalfox file {input_file} -o {output_file} "
               f"--format json --silence --no-color")

        self.run_command(cmd, timeout=600)

        xss_vulns = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    for vuln in data:
                        xss_vulns.append({
                            'type': 'XSS',
                            'url': vuln.get('url', ''),
                            'param': vuln.get('param', ''),
                            'payload': vuln.get('payload', '')
                        })
            except:
                pass

        return xss_vulns

    def run_nuclei_exposures(self, domain: str, urls: List[str]) -> List[Dict]:
        """Focus on exposure templates"""
        self.logger.info(f"[{domain}] Scanning for exposures...")

        input_file = f"{self.config.output_dir}/nuclei/{domain}_exposure_input.txt"
        output_file = f"{self.config.output_dir}/nuclei/{domain}_exposures.json"

        with open(input_file, 'w') as f:
            f.write('\n'.join(urls))

        cmd = (f"nuclei -l {input_file} -t ~/nuclei-templates/exposures/ "
               f"-o {output_file} -silent -json")

        self.run_command(cmd, timeout=600)

        exposures = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        exposures.append({
                            'domain': domain,
                            'type': 'Exposure',
                            'template': data.get('template-id', ''),
                            'host': data.get('host', '')
                        })
                    except:
                        pass

        return exposures

    # ═════════════════════════════════════════════════════════════════
    # PHASE 5: SPECIALIZED SCANS
    # ═════════════════════════════════════════════════════════════════

    def run_paramspider(self, domain: str) -> List[str]:
        """Parameter discovery with ParamSpider"""
        self.logger.info(f"[{domain}] Running ParamSpider...")

        output_dir = f"{self.config.output_dir}/endpoints/{domain}"
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        cmd = f"python3 ~/tools/ParamSpider/paramspider.py -d {domain} -o {output_dir} --level high"
        self.run_command(cmd, timeout=300)

        params = []
        output_file = f"{output_dir}/parameters.txt"
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                params = [line.strip() for line in f if line.strip()]

        return params

    def run_arjun(self, domain: str, urls: List[str]) -> List[Dict]:
        """HTTP parameter discovery with Arjun"""
        self.logger.info(f"[{domain}] Running Arjun for parameter discovery...")

        input_file = f"{self.config.output_dir}/urls/{domain}_arjun_input.txt"
        output_file = f"{self.config.output_dir}/endpoints/{domain}_arjun.json"

        param_urls = [u for u in urls if '?' in u][:50]
        if not param_urls:
            return []

        with open(input_file, 'w') as f:
            f.write('\n'.join(param_urls))

        cmd = f"arjun -i {input_file} -o {output_file} -t {self.config.threads} --stable"
        self.run_command(cmd, timeout=600)

        return []

    def run_js_analysis(self, domain: str, js_urls: List[str]) -> List[Dict]:
        """Analyze JavaScript files for secrets and endpoints"""
        self.logger.info(f"[{domain}] Analyzing JavaScript files...")

        output_dir = f"{self.config.output_dir}/js/{domain}"
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        secrets = []

        for js_url in js_urls[:50]:
            cmd = f"python3 ~/tools/SecretFinder/SecretFinder.py -i {js_url} -o cli"
            result = self.run_command(cmd, timeout=30)

            if 'http' in result or 'api' in result or 'key' in result.lower():
                secrets.append({
                    'url': js_url,
                    'findings': result
                })

        return secrets

    def run_ffuf(self, domain: str, alive_urls: List[str]) -> List[Dict]:
        """Fuzz for hidden directories and files"""
        self.logger.info(f"[{domain}] Running ffuf fuzzing...")

        findings = []
        wordlist = self.config.wordlist.replace('subdomains', 'discovery/Web-Content')

        for url in alive_urls[:10]:
            output_file = f"{self.config.output_dir}/endpoints/{domain}_ffuf.json"

            cmd = (f"ffuf -u {url}/FUZZ -w {wordlist} "
                   f"-o {output_file} -of json -mc 200,204,301,302,403 "
                   f"-t {self.config.threads} -s")

            self.run_command(cmd, timeout=120)

        return findings

    # ═════════════════════════════════════════════════════════════════
    # PHASE 6: REPORTING
    # ═════════════════════════════════════════════════════════════════

    def generate_report(self, domain: str):
        """Generate comprehensive report"""
        self.logger.info(f"[{domain}] Generating report...")

        report_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = f"{self.config.output_dir}/reports/{domain}_report_{report_time}.md"

        domain_vulns = [v for v in self.vulnerabilities if v['domain'] == domain]

        report = f"""# Security Recon Report: {domain}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary
- **Target**: {domain}
- **Total Subdomains**: {len(self.results)}
- **Potential Findings**: {len(domain_vulns)}

## Vulnerability Breakdown
"""

        by_severity = {}
        for v in domain_vulns:
            sev = v.get('severity', 'unknown')
            by_severity.setdefault(sev, []).append(v)

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in by_severity:
                report += f"\n### {severity.upper()} Severity ({len(by_severity[severity])})\n"
                for v in by_severity[severity]:
                    report += f"""
- **{v.get('name', 'Unknown')}**
  - Template: `{v.get('template', 'N/A')}`
  - Host: {v.get('host', 'N/A')}
  - Matched: `{v.get('matched', 'N/A')}`

"""

        quick_wins = [v for v in domain_vulns if 'exposure' in v.get('template', '').lower()
                     or 'default' in v.get('template', '').lower()]

        if quick_wins:
            report += """
## 🎯 Quick Wins (Easy to Verify)
These findings are typically easy to verify and report:
"""
            for v in quick_wins[:10]:
                report += f"- {v.get('name', 'Unknown')}: {v.get('host', 'N/A')}\n"

        report += """
## Recommended Actions

### Immediate
1. Verify all CRITICAL and HIGH severity findings manually
2. Check exposed credentials/API keys for validity
3. Test authentication bypasses on production environments

### Short Term
1. Run Dalfox on all parameterized URLs for XSS
2. Check JavaScript files for hardcoded secrets
3. Test IDOR on API endpoints

### Long Term
1. Monitor for new subdomains continuously
2. Re-scan after fixes to verify resolution
3. Expand to related domains and acquisitions

## Tools Used
- Subfinder, Amass, Assetfinder (Subdomain enumeration)
- Httpx (Live host detection)
- Nuclei (Vulnerability scanning)
- Naabu (Port scanning)
- Waybackurls, Gau (URL collection)
- Dalfox (XSS detection)
- Katana (Web crawling)

---
*Generated by Security Recon Scanner v3.0*
"""

        with open(report_file, 'w') as f:
            f.write(report)

        self.logger.info(f"[{domain}] Report saved: {report_file}")
        return report_file

    def generate_master_report(self):
        """Generate master report for all targets"""
        report_file = f"{self.config.output_dir}/reports/MASTER_REPORT.md"

        all_vulns = len(self.vulnerabilities)
        critical = len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])
        high = len([v for v in self.vulnerabilities if v.get('severity') == 'high'])

        report = f"""# 🎯 SECURITY RECON MASTER REPORT

**Scan Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Total Targets**: {len(self.targets)}
**Total Findings**: {all_vulns}

## Severity Distribution
- 🔴 Critical: {critical}
- 🟠 High: {high}
- 🟡 Medium: {len([v for v in self.vulnerabilities if v.get('severity') == 'medium'])}
- 🔵 Low: {len([v for v in self.vulnerabilities if v.get('severity') == 'low'])}
- ⚪ Info: {len([v for v in self.vulnerabilities if v.get('severity') == 'info'])}

## Top Findings by Severity
"""

        sorted_vulns = sorted(self.vulnerabilities,
                            key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.get('severity', 'info'), 5))

        for i, v in enumerate(sorted_vulns[:20], 1):
            report += f"{i}. **{v.get('name', 'Unknown')}** ({v.get('severity', 'N/A').upper()})\n"
            report += f"   - Domain: {v.get('domain', 'N/A')}\n"
            report += f"   - Host: {v.get('host', 'N/A')}\n\n"

        with open(report_file, 'w') as f:
            f.write(report)

        self.logger.info(f"Master report saved: {report_file}")

    # ═════════════════════════════════════════════════════════════════
    # MAIN SCANNING WORKFLOW
    # ═════════════════════════════════════════════════════════════════

    def scan_single_target(self, domain: str):
        """Full scanning workflow for a single target"""
        self.logger.info(f"{Colors.CYAN}{Colors.BOLD}Starting scan: {domain}{Colors.END}")
        start_time = time.time()

        try:
            print(f"\n{Colors.YELLOW}[Phase 1/6]{Colors.END} Subdomain Enumeration")
            subfinder_results = self.run_subfinder(domain)
            amass_results = self.run_amass(domain)
            assetfinder_results = self.run_assetfinder(domain)

            all_subs = self.merge_subdomains(domain,
                [subfinder_results, amass_results, assetfinder_results])

            if not all_subs:
                self.logger.warning(f"No subdomains found for {domain}")
                return

            print(f"\n{Colors.YELLOW}[Phase 2/6]{Colors.END} HTTP Probing")
            alive_urls = self.run_httpx(domain, all_subs)

            if not alive_urls:
                self.logger.warning(f"No alive hosts for {domain}")
                return

            print(f"\n{Colors.YELLOW}[Phase 3/6]{Colors.END} Port Scanning")
            ports = self.run_naabu(domain)

            print(f"\n{Colors.YELLOW}[Phase 4/6]{Colors.END} URL Collection")
            wayback_urls = self.run_waybackurls(domain)
            gau_urls = self.run_gau(domain)
            katana_urls = self.run_katana(domain, alive_urls)

            all_urls = wayback_urls | gau_urls | katana_urls
            categorized = self.filter_interesting_urls(domain, all_urls)

            print(f"\n{Colors.YELLOW}[Phase 5/6]{Colors.END} Vulnerability Scanning")

            nuclei_results = self.run_nuclei(domain, alive_urls)

            if all_urls:
                url_list = list(all_urls)[:5000]
                self.run_nuclei(domain, url_list,
                              templates="~/nuclei-templates/exposures/,~/nuclei-templates/misconfiguration/")

            if categorized.get('params'):
                self.run_dalfox(domain, categorized['params'])

            self.run_nuclei_exposures(domain, alive_urls)

            print(f"\n{Colors.YELLOW}[Phase 6/6]{Colors.END} Specialized Analysis")
            if categorized.get('js_files'):
                self.run_js_analysis(domain, categorized['js_files'])

            self.generate_report(domain)

            elapsed = time.time() - start_time
            self.logger.info(f"{Colors.GREEN}Completed {domain} in {elapsed:.1f}s{Colors.END}")

        except Exception as e:
            self.logger.error(f"Error scanning {domain}: {e}")
            if self.config.debug:
                import traceback
                traceback.print_exc()

    def run_mass_scan(self, target_file: str):
        """Run scans against mass target list"""
        self.print_banner()
        self.load_targets(target_file)

        self.logger.info(f"Starting mass scan of {len(self.targets)} targets")

        for i, domain in enumerate(self.targets, 1):
            print(f"\n{Colors.MAGENTA}{'='*60}{Colors.END}")
            print(f"{Colors.MAGENTA}Target {i}/{len(self.targets)}: {domain}{Colors.END}")
            print(f"{Colors.MAGENTA}{'='*60}{Colors.END}")

            self.scan_single_target(domain)

        self.generate_master_report()

        print(f"\n{Colors.GREEN}{Colors.BOLD}")
        print("="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"Total Findings: {len(self.vulnerabilities)}")
        print(f"Reports saved in: {self.config.output_dir}/reports/")
        print(f"{Colors.END}")


# ═════════════════════════════════════════════════════════════════════
# INSTALLATION SCRIPT
# ═════════════════════════════════════════════════════════════════════

SETUP_SCRIPT = '''#!/bin/bash
# install_tools.sh - Install all required tools

echo "[*] Installing Security Recon Scanner dependencies..."

sudo apt update

if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

mkdir -p ~/tools
cd ~/tools

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

pip3 install arjun

sudo apt install amass -y

nuclei -update-templates

mkdir -p ~/wordlists
cd ~/wordlists
git clone https://github.com/danielmiessler/SecLists.git

echo "[+] Installation complete! Add to PATH: export PATH=$PATH:$HOME/go/bin"
'''


# ═════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═════════════════════════════════════════════════════════════════════

def create_setup_script():
    """Create installation script"""
    with open('install_tools.sh', 'w') as f:
        f.write(SETUP_SCRIPT)
    os.chmod('install_tools.sh', 0o755)


def main():
    parser = argparse.ArgumentParser(
        description='Security Recon Scanner - Automated recon & vulnerability discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 recon_scanner.py -l targets.txt

  # Debug mode with custom threads
  python3 recon_scanner.py -l targets.txt --debug -t 30

  # Custom nuclei templates
  python3 recon_scanner.py -l targets.txt --nuclei-templates ~/custom-templates/

  # Create installation script
  python3 recon_scanner.py --setup
        """
    )

    parser.add_argument('-l', '--list', required=True,
                       help='File containing list of target domains')
    parser.add_argument('-t', '--threads', type=int, default=20,
                       help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', default='recon_results',
                       help='Output directory (default: recon_results)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode with verbose logging')
    parser.add_argument('--nuclei-templates', default='',
                       help='Custom nuclei templates directory')
    parser.add_argument('--setup', action='store_true',
                       help='Create tool installation script')

    args = parser.parse_args()

    if args.setup:
        create_setup_script()
        print("[+] Created install_tools.sh - Run it to install all tools")
        return

    if not os.path.exists(args.list):
        print(f"[!] Error: Target file not found: {args.list}")
        sys.exit(1)

    config = Config(
        threads=args.threads,
        output_dir=args.output,
        debug=args.debug,
        nuclei_templates=args.nuclei_templates
    )

    scanner = ReconScanner(config)
    scanner.run_mass_scan(args.list)


if __name__ == '__main__':
    main()
