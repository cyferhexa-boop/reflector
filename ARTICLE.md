# Reflector v1.0.0: Advanced Parameter Reflection Scanner for Bug Bounty Hunters

**A comprehensive, production-ready tool for discovering XSS and SQL injection vulnerabilities through parameter reflection analysis**

---

## 🎯 Short Description

Reflector is a professional-grade parameter reflection scanner that combines multiple URL collection sources with intelligent vulnerability detection. Built for bug bounty hunters and penetration testers, it automatically discovers parameter-based vulnerabilities including XSS, SQL injection, and reflection flaws across web applications.

---

## 📖 Article Description

### The Challenge of Modern Web Application Testing

In today's complex web application landscape, finding parameter-based vulnerabilities requires more than just testing a few obvious endpoints. Modern applications have hundreds of parameters scattered across different pages, APIs, and legacy systems. Traditional tools often miss critical attack surfaces because they rely on limited URL discovery methods.

**Reflector solves this problem** by implementing a comprehensive multi-source URL collection strategy combined with intelligent vulnerability detection, making it the most thorough parameter reflection scanner available.

### What Makes Reflector Different

Unlike traditional scanners that rely on single sources like Wayback Machine, Reflector aggregates URLs from **8+ different intelligence sources**:

- **Historical Archives**: Wayback Machine, Common Crawl
- **Security Intelligence**: URLScan.io, AlienVault OTX, VirusTotal
- **Certificate Transparency**: crt.sh subdomain discovery
- **Deep Web Intelligence**: Intelligence X phonebook search
- **Live Crawling**: Real-time web crawler (hakrawler-style)
- **Smart Generation**: AI-powered endpoint prediction

This multi-source approach ensures **maximum attack surface coverage** - finding URLs that other tools miss.

### Advanced Vulnerability Detection

Reflector doesn't just find reflections; it intelligently classifies vulnerabilities:

- **🟡 XSS**: HTML tags reflected without encoding
- **🔴 SQL**: Database error messages in responses  
- **🟡+🔴 XSS+SQL**: Both vulnerabilities in same parameter (critical finding)
- **🔵 REFLECTION**: Basic reflection (informational)

The tool uses smart payload analysis to distinguish between exploitable vulnerabilities and harmless reflections, reducing false positives significantly.

### Production-Ready Architecture

Built with enterprise-grade features:

- **Async Processing**: High-performance concurrent scanning
- **Error Resilience**: Continues working even if major sources fail
- **Resource Management**: Automatic cleanup and memory optimization
- **Professional Output**: Multiple export formats (JSON, CSV, TXT)
- **Comprehensive Logging**: Detailed audit trails for professional engagements

---

## 🚀 Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/nrs/reflector.git
cd reflector

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x reflector.py

# Optional: Create system-wide command
sudo ln -sf $(pwd)/reflector.py /usr/local/bin/reflector
```

### Dependencies
```bash
pip install aiohttp beautifulsoup4
```

---

## 💡 Usage Examples

### Basic Scanning
```bash
# Comprehensive scan (recommended)
python3 reflector.py example.com

# Fast scan (skip reachability check)
python3 reflector.py example.com --fast

# Wayback-only scan (fastest)
python3 reflector.py example.com --wayback-only
```

### Advanced Usage
```bash
# High-performance scan with custom payload
python3 reflector.py target.com --fast -c 100 -p "<script>alert(1)</script>"

# Professional scan with logging and export
python3 reflector.py target.com -o results.json --log-file scan.log

# Scan from custom URL list
python3 reflector.py -f urls.txt --show-all

# Enhanced scan with API keys
python3 reflector.py target.com --vt-key YOUR_VT_KEY --intelx-key YOUR_IX_KEY
```

### Integration Examples
```bash
# Subdomain enumeration + reflection testing
subfinder -d example.com | httpx -silent | python3 reflector.py -f -

# Combine with other recon tools
cat discovered_urls.txt | python3 reflector.py -f - --fast -o findings.json
```

---

## ⭐ Key Features

### 🕷️ **Multi-Source URL Collection**
- **Wayback Machine**: Historical URL archives
- **Common Crawl**: Web crawl data archives  
- **URLScan.io**: Security scan database with DOM analysis
- **AlienVault OTX**: Threat intelligence feeds
- **VirusTotal**: Malware analysis URL database
- **Intelligence X**: Deep web phonebook search
- **crt.sh**: Certificate transparency subdomain discovery
- **Live Web Crawler**: Real-time hakrawler-style crawling
- **Smart Generation**: 1000+ endpoint patterns

### 🎯 **Intelligent Vulnerability Detection**
- **XSS Detection**: HTML tag reflection analysis
- **SQL Injection**: Database error pattern matching
- **Combined Detection**: XSS+SQL in same parameter
- **Smart Filtering**: Distinguishes exploitable vs harmless reflections
- **Custom Payloads**: Support for specialized test cases

### ⚡ **Performance & Reliability**
- **Async Processing**: Up to 200 concurrent requests
- **Error Resilience**: Continues if sources fail
- **Smart Timeouts**: Optimized for reliability
- **Resource Management**: Automatic cleanup
- **Progress Tracking**: Real-time scan statistics

### 📊 **Professional Output**
- **Multiple Formats**: JSON, CSV, TXT export
- **Color-coded Console**: Easy vulnerability identification
- **Detailed Reporting**: Domain, path, parameter breakdown
- **Statistics Summary**: Comprehensive scan metrics
- **Integration Ready**: JSON output for tool chaining

### 🛡️ **Enterprise Features**
- **Comprehensive Logging**: Audit trail support
- **API Key Support**: Enhanced results with VirusTotal/Intelligence X
- **Batch Processing**: Handle large URL lists
- **Memory Efficient**: Optimized for large-scale scans
- **Clean Architecture**: Modular, maintainable codebase

---

## 📈 **Performance Metrics**

- **Speed**: 50+ tests/second on modern hardware
- **Coverage**: 8+ URL intelligence sources
- **Accuracy**: Smart vulnerability classification
- **Scalability**: Handles 100K+ URLs efficiently
- **Reliability**: Fault-tolerant multi-source approach

---

## 🎯 **Use Cases**

### Bug Bounty Hunting
- **Comprehensive Discovery**: Find hidden parameter endpoints
- **Vulnerability Classification**: Prioritize critical findings
- **Efficient Workflow**: Fast scans for large scope programs
- **Professional Reporting**: Export findings for submission

### Penetration Testing
- **Attack Surface Mapping**: Complete parameter inventory
- **Vulnerability Assessment**: Systematic reflection testing
- **Client Reporting**: Professional output formats
- **Audit Trails**: Comprehensive logging support

### Security Research
- **Large-scale Analysis**: Batch processing capabilities
- **Data Export**: Multiple formats for analysis
- **Custom Payloads**: Specialized research scenarios
- **Integration**: Works with existing toolchains

---

## 🔧 **Command Reference**

### Core Options
```bash
-f, --file          File containing URLs to test
-c, --concurrency   Concurrent workers (default: 20, max: 200)
-p, --payload       Custom payload (default: <a>Reflected::</a>)
-o, --output        Output file (.json, .csv, .txt)
-t, --timeout       Request timeout (default: 8 seconds)
```

### Performance Options
```bash
--fast              Skip reachability check (much faster)
--wayback-only      Only use Wayback Machine (fastest)
--show-all          Display all results (no truncation)
```

### Professional Options
```bash
--vt-key            VirusTotal API key (enhanced results)
--intelx-key        Intelligence X API key (enhanced results)
--log-file          Detailed logging to file
--verbose           Enable debug output
--no-cleanup        Keep temporary files for analysis
```

---

## 📊 **Sample Output**

### Console Output
```bash
[*] Collecting URLs from enhanced sources for: target.com
[*] Wayback: 8,234 URLs -> wayback_urls.txt
[*] Common Crawl: 12,456 URLs -> commoncrawl_urls.txt
[*] URLScan Enhanced: 5,891 URLs -> urlscan_urls.txt
[*] Web Crawler: 892 URLs -> webcrawler_urls.txt
[*] Deduplicated to 15,247 unique parameterized URLs
[*] Testing 15,247 parameter combinations...

[+] XSS+SQL: https://target.com/search?q=<a>Reflected::</a> param=q
[+] XSS: https://api.target.com/users?name=<a>Reflected::</a> param=name
[+] SQL: https://target.com/product?id=<a>Reflected::</a> param=id
[+] REFLECTION: https://target.com/page?data=<a>Reflected::</a> param=data

[+] Found 25 vulnerabilities
======================================================================
                              SCAN SUMMARY                              
======================================================================
[*] Scan Duration: 0:04:32
[*] Test Rate: 55.67 tests/second
[*] URLs Collected: 27,473
[*] Parameterized URLs: 15,247
[*] Tests Performed: 15,247
[+] Vulnerabilities Found: 25

Vulnerability Types:
  XSS+SQL: 3
  XSS: 12
  SQL: 5
  REFLECTION: 5
======================================================================
```

### JSON Export
```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:00",
    "total_vulnerabilities": 25,
    "tool": "Reflector v1.0.0",
    "author": "NRS"
  },
  "vulnerabilities": [
    {
      "vuln_type": "XSS+SQL",
      "param": "search",
      "url": "https://target.com/search?q=<a>Reflected::</a>",
      "type": "body",
      "status": 200
    }
  ]
}
```

---

## 🏆 **Why Choose Reflector?**

### Comprehensive Coverage
- **8+ URL Sources**: Maximum attack surface discovery
- **Historical + Live**: Both archived and current endpoints
- **Smart Deduplication**: Efficient processing of large datasets

### Accurate Detection
- **Multi-vulnerability**: Detects XSS, SQL, and combined issues
- **Low False Positives**: Smart payload analysis
- **Contextual Classification**: Distinguishes exploitable from harmless

### Professional Grade
- **Enterprise Ready**: Production-quality architecture
- **Integration Friendly**: JSON output for automation
- **Audit Support**: Comprehensive logging and reporting

### Performance Optimized
- **High Speed**: 50+ tests/second capability
- **Resource Efficient**: Optimized memory usage
- **Fault Tolerant**: Continues working despite source failures

---

## 🤝 **Contributing**

Reflector is actively maintained and welcomes contributions:

- **Bug Reports**: Submit issues with detailed reproduction steps
- **Feature Requests**: Suggest new URL sources or detection methods
- **Code Contributions**: Follow the modular architecture patterns
- **Documentation**: Help improve usage examples and guides

---

## 📄 **License**

MIT License - Free for commercial and personal use.

---

## 🙏 **Acknowledgments**

- Inspired by hakrawler, waybackurls, and other OSINT tools
- Built with modern async Python for maximum performance
- Designed for the bug bounty and penetration testing community

---

**Reflector v1.0.0** - Making parameter reflection testing comprehensive, accurate, and professional.

**Made with ❤️ by NRS**

*Ready to discover vulnerabilities others miss? Start your comprehensive parameter reflection testing today.*
