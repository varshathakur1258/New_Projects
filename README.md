# Web Vulnerability Scanner

A simple Python-based web vulnerability scanner that checks for common security issues in web applications.

## Features

- HTTP Security Headers Check
- SSL/TLS Configuration Analysis
- Open Port Scanning
- Basic XSS Vulnerability Detection
- Colored Console Output

## Prerequisites

- Python 3.7+
- Nmap installed on your system (required for port scanning)

## Installation

1. Clone this repository or download the files
2. Install the required Python packages:
```bash
pip install -r requirements.txt
```

3. Install Nmap:
   - Windows: Download and install from [Nmap's official website](https://nmap.org/download.html)
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

## Usage

1. Run the scanner:
```bash
python web_vulnerability_scanner.py
```

2. Enter the target URL when prompted (e.g., example.com or https://example.com)

3. The tool will perform the following checks:
   - Security headers analysis
   - SSL/TLS configuration check
   - Open port scanning
   - Basic XSS vulnerability detection

## Security Notice

This tool is for educational and testing purposes only. Always ensure you have permission to scan the target website. Unauthorized scanning of websites may be illegal in your jurisdiction.

## Limitations

- Basic vulnerability checks only
- May produce false positives
- Limited to common vulnerabilities
- No deep scanning or exploitation capabilities

## License

This project is licensed under the MIT License. 