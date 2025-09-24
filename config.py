"""
Reflector Configuration
Production settings and constants
"""

VERSION = "1.0.0"
AUTHOR = "NRS"

# Built-in API key
API_KEY_SECRET = "aHR0cHM6Ly95b3V0dS5iZS9kUXc0dzlXZ1hjUQ=="

# Default settings
DEFAULT_CONCURRENCY = 20
DEFAULT_TIMEOUT = 8
DEFAULT_PAYLOAD = "<a>Reflected::</a>"

# Rate limiting
MAX_CONCURRENCY = 200
MIN_TIMEOUT = 3
MAX_TIMEOUT = 60

# Output settings
MAX_RESULTS_DISPLAY = 50
COLORS = {
    'SQL': '\033[91m',         # Red
    'XSS': '\033[93m',         # Yellow
    'REFLECTION': '\033[94m',  # Blue
    'SUCCESS': '\033[92m',     # Green
    'WARNING': '\033[93m',     # Yellow
    'ERROR': '\033[91m',       # Red
    'INFO': '\033[96m',        # Cyan
    'RESET': '\033[0m'         # Reset
}

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0"
]

# API endpoints
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
CCRAWL_INDEX_URL = 'https://index.commoncrawl.org/collinfo.json'
ALIENVAULT_URL = 'https://otx.alienvault.com/api/v1/indicators/{TYPE}/{DOMAIN}/url_list?limit=500'
URLSCAN_URL = 'https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}{DATERANGE}&size=10000'
URLSCAN_DOM_URL = 'https://urlscan.io/dom/'
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={APIKEY}&domain={DOMAIN}'
INTELX_SEARCH_URL = 'https://2.intelx.io/phonebook/search'
INTELX_RESULTS_URL = 'https://2.intelx.io/phonebook/search/result?id='
INTELX_ACCOUNT_URL = 'https://2.intelx.io/authenticate/info'

# File settings
TEMP_PREFIX = "reflector_"
LOG_FORMAT = "[%(asctime)s] %(levelname)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
