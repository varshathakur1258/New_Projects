#!/usr/bin/env python3
"""
Simple Website Vulnerability Scanner
Educational tool for basic security testing on websites you own or have permission to test.
"""

import requests
import sys
import urllib.parse
from urllib.robotparser import RobotFileParser
import ssl
import socket
from datetime import datetime
import re

class WebVulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebVulnScanner/1.0 (Educational Tool)'
        })
        self.vulnerabilities = []
    
    def scan(self):
        """Run all vulnerability checks"""
        print(f"Starting vulnerability scan for: {self.target_url}")
        print("=" * 60)
        
        try:
            # Basic connectivity check
            response = self.session.get(self.target_url, timeout=10)
            print(f"✓ Target is reachable (Status: {response.status_code})")
        except requests.RequestException as e:
            print(f"✗ Cannot reach target: {e}")
            return
        
        # Run vulnerability checks
        self.check_ssl_certificate()
        self.check_security_headers()
        self.check_directory_traversal()
        self.check_sql_injection_basic()
        self.check_xss_basic()
        self.check_sensitive_files()
        self.check_server_info()
        
        # Display results
        self.display_results()
    
    def check_ssl_certificate(self):
        """Check SSL certificate validity"""
        print("\n[+] Checking SSL Certificate...")
        
        if not self.target_url.startswith('https://'):
            self.vulnerabilities.append({
                'type': 'SSL',
                'severity': 'Medium',
                'description': 'Website not using HTTPS'
            })
            print("  ⚠ No HTTPS detected")
            return
        
        try:
            hostname = urllib.parse.urlparse(self.target_url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            # Check certificate expiration
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            if days_until_expiry < 30:
                self.vulnerabilities.append({
                    'type': 'SSL',
                    'severity': 'High' if days_until_expiry < 0 else 'Medium',
                    'description': f'SSL certificate expires in {days_until_expiry} days'
                })
                print(f"  ⚠ Certificate expires in {days_until_expiry} days")
            else:
                print(f"  ✓ SSL certificate valid (expires in {days_until_expiry} days)")
                
        except Exception as e:
            self.vulnerabilities.append({
                'type': 'SSL',
                'severity': 'High',
                'description': f'SSL certificate error: {str(e)}'
            })
            print(f"  ⚠ SSL error: {e}")
    
    def check_security_headers(self):
        """Check for important security headers"""
        print("\n[+] Checking Security Headers...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
                    print(f"  ⚠ Missing: {header}")
                else:
                    print(f"  ✓ Found: {header}")
            
            if missing_headers:
                self.vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'Medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}'
                })
                
        except requests.RequestException as e:
            print(f"  ✗ Error checking headers: {e}")
    
    def check_directory_traversal(self):
        """Basic directory traversal check"""
        print("\n[+] Checking Directory Traversal...")
        
        payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?file={payload}"
                response = self.session.get(test_url, timeout=5)
                
                if 'root:' in response.text or 'localhost' in response.text:
                    self.vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'description': f'Possible directory traversal with payload: {payload}'
                    })
                    print(f"  ⚠ Potential vulnerability with payload: {payload}")
                    return
                    
            except requests.RequestException:
                continue
        
        print("  ✓ No obvious directory traversal vulnerabilities found")
    
    def check_sql_injection_basic(self):
        """Basic SQL injection check"""
        print("\n[+] Checking SQL Injection (Basic)...")
        
        payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1"]
        
        # Test common parameter names
        params_to_test = ['id', 'user', 'page', 'search', 'q']
        
        for param in params_to_test:
            for payload in payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Look for common SQL error messages
                    sql_errors = [
                        'mysql_fetch_array',
                        'ORA-01756',
                        'Microsoft OLE DB Provider',
                        'SQLServer JDBC Driver',
                        'PostgreSQL query failed',
                        'Warning: mysql_'
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'description': f'Possible SQL injection in parameter "{param}" with payload: {payload}'
                            })
                            print(f"  ⚠ Potential SQL injection in parameter: {param}")
                            return
                            
                except requests.RequestException:
                    continue
        
        print("  ✓ No obvious SQL injection vulnerabilities found")
    
    def check_xss_basic(self):
        """Basic XSS check"""
        print("\n[+] Checking Cross-Site Scripting (Basic)...")
        
        payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "javascript:alert('XSS')"
        ]
        
        params_to_test = ['search', 'q', 'name', 'comment', 'message']
        
        for param in params_to_test:
            for payload in payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'description': f'Possible XSS in parameter "{param}"'
                        })
                        print(f"  ⚠ Potential XSS vulnerability in parameter: {param}")
                        return
                        
                except requests.RequestException:
                    continue
        
        print("  ✓ No obvious XSS vulnerabilities found")
    
    def check_sensitive_files(self):
        """Check for sensitive files"""
        print("\n[+] Checking Sensitive Files...")
        
        sensitive_files = [
            '/robots.txt',
            '/.git/config',
            '/admin',
            '/phpmyadmin',
            '/wp-admin',
            '/.env',
            '/config.php',
            '/backup.sql'
        ]
        
        found_files = []
        for file_path in sensitive_files:
            try:
                response = self.session.get(self.target_url + file_path, timeout=5)
                if response.status_code == 200:
                    found_files.append(file_path)
                    print(f"  ⚠ Accessible file found: {file_path}")
                    
            except requests.RequestException:
                continue
        
        if found_files:
            self.vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Medium',
                'description': f'Sensitive files accessible: {", ".join(found_files)}'
            })
        else:
            print("  ✓ No sensitive files found")
    
    def check_server_info(self):
        """Check server information disclosure"""
        print("\n[+] Checking Server Information...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            server_header = response.headers.get('Server', 'Not disclosed')
            x_powered_by = response.headers.get('X-Powered-By', 'Not disclosed')
            
            print(f"  Server: {server_header}")
            print(f"  X-Powered-By: {x_powered_by}")
            
            if server_header != 'Not disclosed' and any(info in server_header.lower() for info in ['apache', 'nginx', 'iis']):
                # Check if version is disclosed
                if re.search(r'\d+\.\d+', server_header):
                    self.vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': f'Server version disclosed: {server_header}'
                    })
                    
        except requests.RequestException as e:
            print(f"  ✗ Error checking server info: {e}")
    
    def display_results(self):
        """Display scan results"""
        print("\n" + "=" * 60)
        print("VULNERABILITY SCAN RESULTS")
        print("=" * 60)
        
        if not self.vulnerabilities:
            print("✓ No vulnerabilities detected in this basic scan.")
            print("\nNote: This is a basic scan. Consider using professional tools for comprehensive testing.")
            return
        
        # Group by severity
        high_vulns = [v for v in self.vulnerabilities if v['severity'] == 'High']
        medium_vulns = [v for v in self.vulnerabilities if v['severity'] == 'Medium']
        low_vulns = [v for v in self.vulnerabilities if v['severity'] == 'Low']
        
        if high_vulns:
            print(f"\n🔴 HIGH SEVERITY ({len(high_vulns)}):")
            for vuln in high_vulns:
                print(f"  • {vuln['type']}: {vuln['description']}")
        
        if medium_vulns:
            print(f"\n🟡 MEDIUM SEVERITY ({len(medium_vulns)}):")
            for vuln in medium_vulns:
                print(f"  • {vuln['type']}: {vuln['description']}")
        
        if low_vulns:
            print(f"\n🟢 LOW SEVERITY ({len(low_vulns)}):")
            for vuln in low_vulns:
                print(f"  • {vuln['type']}: {vuln['description']}")
        
        print(f"\nTotal vulnerabilities found: {len(self.vulnerabilities)}")
        print("\nIMPORTANT: This is a basic educational scanner.")
        print("For production systems, use professional security testing tools.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python vuln_scanner.py <target_url>")
        print("Example: python vuln_scanner.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Basic URL validation
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    print("⚠️  IMPORTANT DISCLAIMER ⚠️")
    print("This tool is for educational purposes and authorized testing only.")
    print("Only use this scanner on websites you own or have explicit permission to test.")
    print("Unauthorized scanning may be illegal in your jurisdiction.")
    print()
    
    scanner = WebVulnScanner(target_url)
    scanner.scan()

if __name__ == "__main__":
    main()