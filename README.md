# 🔍 Shadow - Automated Reconnaissance & Vulnerability Scanner

**Shadow** is a comprehensive automated reconnaissance and vulnerability scanning tool designed for security professionals and penetration testers. It combines multiple scanning techniques including DNS enumeration, subdomain discovery, port scanning, technology detection, web crawling, and vulnerability assessment in a single, easy-to-use framework.

## ⚡ Features

### Reconnaissance Phase
- **DNS Enumeration**: Discover A, AAAA, MX, NS, and TXT records
- **Subdomain Enumeration**: Find subdomains using wordlist-based brute force
- **Port Scanning**: Scan common and custom ports with service identification
- **Technology Detection**: Identify web frameworks, libraries, and server technologies
- **Web Crawling**: Discover endpoints, JavaScript files, forms, and URL parameters
- **WHOIS Information**: Retrieve domain registration details

### Vulnerability Scanning
- **Custom Security Checks**:
  - Missing security headers detection
  - Information disclosure vulnerabilities
  - Directory listing detection
  - Backup file exposure checks
- **Nikto Integration**: Web server vulnerability scanner
- **Nuclei Integration**: Configurable vulnerability templates

### Reporting
- **HTML Reports**: Rich, formatted vulnerability reports with severity badges
- **JSON Reports**: Machine-readable output for integration with other tools
- **Detailed Findings**: Comprehensive descriptions and recommendations

## 🛠️ Requirements

### System Dependencies
- Python 3.10+
- Nikto (for web server scanning)
- Nuclei (for advanced vulnerability detection)
- DNS utilities

### Python Dependencies
```
aiohttp>=3.8.0
dnspython>=2.3.0
requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
python-whois>=0.8.0
tqdm>=4.64.0
urllib3>=1.26.0
```

## 📦 Installation

### Method 1: Direct Installation

1. Clone the repository:
```bash
git clone https://github.com/sabit-rashid/Shadow.git
cd Shadow
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install system dependencies:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nikto nuclei
```

**macOS:**
```bash
brew install nikto
# For nuclei, visit: https://github.com/projectdiscovery/nuclei
```

### Method 2: Docker

Build and run using Docker:
```bash
docker build -t shadow:latest .
docker run -v $(pwd)/results:/home/scanner shadow:latest example.com
```

## 🚀 Usage

### Basic Scan
```bash
python main.py example.com
```

### Advanced Usage
```bash
# Scan with custom threads and URL limit
python main.py https://example.com --threads 20 --max-urls 200

# Scan specific ports
python main.py 192.168.1.1 --ports 80,443,8080,8443

# Skip specific scans
python main.py example.com --skip-nikto --skip-nuclei --skip-crawl
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target domain, URL, or IP address | Required |
| `--threads` | Number of concurrent threads | 10 |
| `--max-urls` | Maximum URLs to crawl | 100 |
| `--ports` | Comma-separated ports to scan | Common ports |
| `--skip-nikto` | Skip Nikto vulnerability scan | False |
| `--skip-nuclei` | Skip Nuclei vulnerability scan | False |
| `--skip-crawl` | Skip web crawling phase | False |

## 📋 Output

### Report Files
- `security_report.html` - Rich HTML report with interactive findings
- `security_report.json` - Structured JSON format for automation
- `scan_results/` - Individual scan output files from Nikto and Nuclei

### Console Output
Shadow provides color-coded console output showing:
- Real-time scan progress
- Discovered findings
- Vulnerability counts by severity
- Scan completion summary

## 🔄 Scanning Workflow

### Phase 1: Reconnaissance
1. DNS enumeration
2. Subdomain enumeration
3. Port scanning
4. Technology detection
5. Web crawling
6. Form and parameter discovery

### Phase 2: Vulnerability Scanning
1. Custom security checks (fast)
2. Nikto web server scan
3. Nuclei template-based scanning

### Phase 3: Report Generation
1. HTML report generation
2. JSON report generation
3. Summary display

## 🛡️ Security Considerations

- **Educational Use**: This tool is intended for authorized security testing only
- **Authorization Required**: Always obtain written permission before scanning
- **Legal Compliance**: Ensure compliance with all applicable laws and regulations
- **Rate Limiting**: Built-in delays between requests to minimize impact
- **SSL Warnings**: Suppresses SSL verification warnings for self-signed certificates

## 📊 Understanding the Reports

### Severity Levels
- 🔴 **Critical**: Immediate exploitation possible, high impact
- 🟠 **High**: Likely exploitable, significant impact
- 🟡 **Medium**: Possible exploitation, moderate impact
- 🔵 **Low**: Difficult exploitation, minimal impact

### Report Sections

**Executive Summary**
- Target information
- Total vulnerability count by severity
- Quick overview of findings

**Reconnaissance Findings**
- DNS records
- Open ports and services
- Detected technologies
- Discovered endpoints

**Vulnerability Findings**
- Detailed vulnerability descriptions
- Severity ratings
- Recommendations for remediation
- Tool source (Nikto, Nuclei, or Custom)

## 🔧 Configuration

### Custom Subdomains Wordlist
Create a `subdomains.txt` file in the project directory with one subdomain per line:
```
www
mail
ftp
api
admin
staging
```

Then use:
```bash
python main.py example.com --wordlist subdomains.txt
```

### Custom Nuclei Templates
Nuclei templates are automatically downloaded and updated. To use specific templates:
```bash
python main.py example.com
# Nuclei will prompt for template selection
```

## 📝 Example Scan Output

```
============================================================
  Automated Reconnaissance & Vulnerability Scanner
============================================================

[INFO] Starting scan on target: example.com

[Phase 1] Reconnaissance
----------------------------------------
[INFO] Performing DNS enumeration...
[SUCCESS] Found 2 A records
[INFO] Enumerating subdomains...
[SUCCESS] Found 5 subdomains
[INFO] Scanning for open ports...
[SUCCESS] Found 3 open ports
[INFO] Detecting technologies...
[SUCCESS] Detected 6 technologies

[Phase 2] Vulnerability Scanning
----------------------------------------
[INFO] Performing custom vulnerability checks...
[SUCCESS] Custom checks found 4 issues
[INFO] Running Nikto vulnerability scanner...
[SUCCESS] Nikto found 12 potential issues

[Phase 3] Report Generation
----------------------------------------
[SUCCESS] HTML report generated: security_report.html
[SUCCESS] JSON report generated: security_report.json

============================================================
  Scan Complete
============================================================

[SUCCESS] Scan completed in 285.42 seconds
[INFO] Endpoints discovered: 47
[INFO] JavaScript files found: 23
[INFO] Total vulnerabilities found: 16
[WARNING] Review the HTML report for detailed findings
```

## 🐛 Troubleshooting

### "Nikto is not installed" Error
```bash
# Install Nikto
sudo apt-get install nikto  # Ubuntu/Debian
brew install nikto           # macOS
```

### "Missing required package" Error
```bash
pip install -r requirements.txt
```

### SSL Certificate Errors
The tool automatically bypasses SSL verification warnings. To verify SSL certificates, modify:
```python
response = self.session.get(target_url, timeout=10, verify=True)
```

### Timeout Issues
Increase timeout values in the code or reduce `--max-urls`:
```bash
python main.py example.com --max-urls 50 --threads 5
```

## 📚 API Usage

Use Shadow as a Python module in your own scripts:

```python
import asyncio
from main import AutomatedScanner

async def main():
    scanner = AutomatedScanner(
        target="example.com",
        threads=10,
        max_urls=100
    )
    results = await scanner.run()
    print(results)

asyncio.run(main())
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

**Disclaimer**: This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have proper authorization before scanning any targets.

## 👤 Author

**Sabit Rashid** - [GitHub Profile](https://github.com/sabit-rashid)

## 🙏 Acknowledgments

- [Nikto](https://github.com/sullo/nikto) - Web server scanner
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- [AIOHTTP](https://aiohttp.readthedocs.io/) - Async HTTP client

## 📞 Support

For issues, questions, or suggestions, please open an issue on GitHub.
