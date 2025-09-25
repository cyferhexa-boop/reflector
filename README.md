# Reflector v1.0.0

**Professional Parameter Reflection Scanner** - Production-ready tool for finding XSS and reflection vulnerabilities.

Made by **NRS**

## 🚀 Features

- **Multi-Source URL Collection**: Wayback Machine, Common Crawl, URLScan.io, AlienVault OTX, GitHub search
- **Intelligent Filtering**: Automatic parameter detection and deduplication
- **Vulnerability Detection**: XSS and reflection vulnerability identification
- **Professional Output**: Color-coded console output with multiple export formats
- **Production Ready**: Comprehensive logging, statistics, and error handling
- **High Performance**: Async processing with configurable concurrency
- **Easy to Use**: Simple CLI with sensible defaults

## 📦 Installation

```bash
git clone [https://github.com/nrs/reflector.git](https://github.com/cyferhexa-boop/reflector.git)
cd reflector
chmod +x install.sh
./install.sh
```

Or manual installation:
```bash
pip3 install -r requirements.txt
chmod +x reflector.py
```

## 🎯 Quick Start

```bash
# Basic scan
python3 reflector.py example.com

# Fast Wayback-only scan  
python3 reflector.py example.com --wayback-only

# High-performance scan with logging
python3 reflector.py target.com -c 100 -o results.json --log-file scan.log

# Scan from URL file
python3 reflector.py -f urls.txt --show-all
```

## 📋 Usage

```
Reflector v1.0.0 - Professional Parameter Reflection Scanner

USAGE:
    python3 reflector.py <domain> [options]
    python3 reflector.py -f <url_file> [options]

OPTIONS:
    -f, --file          File containing URLs to test
    -c, --concurrency   Number of concurrent workers (default: 20, max: 200)
    -p, --payload       Custom payload (default: <a>Reflected::</a>)
    -o, --output        Output file (supports .json, .csv, .txt)
    -t, --timeout       Request timeout in seconds (default: 8)
    --wayback-only      Only use Wayback Machine (faster)
    --show-all          Display all results (no truncation)
    --log-file          Save detailed logs to file
    --no-cleanup        Don't delete temporary files
    --verbose           Enable verbose logging
    -h, --help          Show this help menu
```

## 📊 Output Formats

### Console Output
```
[+] Found 15 vulnerabilities
================================================================================

[XSS] - 8 found
------------------------------------------------------------
 1. Parameter: search
    Domain:    example.com
    Path:      /search
    Location:  body
    Status:    200
    URL:       https://example.com/search?q=<a>Reflected::</a>

[REFLECTION] - 7 found
------------------------------------------------------------
 1. Parameter: id
    Domain:    api.example.com
    Path:      /user
    Location:  header:X-Debug
    Status:    200
    URL:       https://api.example.com/user?id=<a>Reflected::</a>
```

### JSON Output (`-o results.json`)
```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:00",
    "total_vulnerabilities": 15,
    "tool": "Reflector v1.0.0",
    "author": "NRS"
  },
  "vulnerabilities": [
    {
      "vuln_type": "XSS",
      "param": "search",
      "url": "https://example.com/search?q=<a>Reflected::</a>",
      "type": "body",
      "status": 200
    }
  ]
}
```

### Statistics Summary
```
======================================================================
                              SCAN SUMMARY                              
======================================================================
[*] Scan Duration: 0:02:45
[*] Test Rate: 45.67 tests/second
[*] URLs Collected: 12,450
[*] Parameterized URLs: 3,247
[*] Tests Performed: 7,891
[+] Vulnerabilities Found: 15

Vulnerability Types:
  XSS: 8
  REFLECTION: 7

Top Vulnerable Parameters:
  search: 3
  id: 2
  query: 2

URL Sources:
  Wayback Machine: 8,234 URLs
  Common Crawl: 2,156 URLs
  URLScan.io: 1,234 URLs
  GitHub Search: 456 URLs
  AlienVault OTX: 370 URLs
======================================================================
```

### Custom Payloads
```bash
# XSS payload
python3 reflector.py target.com -p "<script>alert(1)</script>"

# SSTI payload  
python3 reflector.py target.com -p "{{7*7}}"

# Custom reflection test
python3 reflector.py target.com -p "CUSTOM_REFLECT_TEST"
```

### Performance Tuning
```bash
# High concurrency for fast networks
python3 reflector.py target.com -c 200 -t 5

# Conservative settings for slow targets
python3 reflector.py target.com -c 10 -t 15

# Wayback-only for quick reconnaissance
python3 reflector.py target.com --wayback-only -c 50
```

### Integration Examples
```bash
# Subdomain enumeration + reflection testing
subfinder -d example.com | httpx -silent | python3 reflector.py -f -

# Combine with other tools
cat urls.txt | python3 reflector.py -f - -o results.json
```

## 🛡️ Responsible Usage

- Only test domains you own or have explicit permission to test
- Respect rate limits and don't overload target servers
- Use appropriate concurrency settings for the target
- Follow responsible disclosure for any vulnerabilities found

## 📈 Performance

- **Speed**: 50+ tests/second on modern hardware
- **Memory**: ~50MB RAM usage for typical scans
- **Scalability**: Handles 100K+ URLs efficiently
- **Reliability**: Robust error handling and recovery

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by various OSINT and security tools
- Built with modern async Python for performance
- Designed for professional security testing workflows

---

**Reflector v1.0.0** - Making parameter reflection testing professional and efficient.

Made with ❤️ by **NRS**
