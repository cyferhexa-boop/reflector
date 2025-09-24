import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Set, Tuple

class ReflectionScanner:
    def __init__(self, concurrency: int = 20, payload: str = "<a>Reflected::</a>", timeout: int = 8, stats=None):
        self.concurrency = concurrency
        self.payload = payload
        self.timeout = timeout
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        self.total_tests = 0
        self.completed_tests = 0
        self.stats = stats
    
    def _normalize_url(self, url: str) -> str:
        """Add https if no scheme present"""
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url.lstrip('/')
        return url
    
    def _build_test_urls(self, base_url: str) -> List[Tuple[str, str]]:
        """Generate test URLs by injecting payload into each parameter"""
        url = self._normalize_url(base_url)
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        test_urls = []
        for param_name in params.keys():
            # Create copy and inject payload
            test_params = {k: v[:] for k, v in params.items()}
            test_params[param_name] = [self.payload]
            
            # Rebuild URL
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme or 'https',
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            test_urls.append((test_url, param_name))
        
        return test_urls
    
    def _detect_vulnerability_type(self, content: str) -> Optional[str]:
        """Detect if payload is reflected without encoding and determine vuln type"""
        # Check if payload is reflected exactly (unencoded)
        if self.payload not in content:
            return None
        
        # Check for XSS indicators
        xss_indicators = ["<a>", "</a>", "<", ">"]
        xss_found = any(indicator in content for indicator in xss_indicators)
        
        # Check for SQL injection indicators
        sql_indicators = [
            "sql syntax", "mysql_fetch", "ora-", "microsoft odbc", 
            "sqlite_", "postgresql", "warning: mysql", "error in your sql",
            "mysql error", "ora-00", "sqlite error", "syntax error",
            "unclosed quotation mark", "quoted string not properly terminated"
        ]
        sql_found = any(indicator.lower() in content.lower() for indicator in sql_indicators)
        
        # Determine vulnerability type
        if xss_found and sql_found:
            return "XSS+SQL"
        elif sql_found:
            return "SQL"
        elif xss_found:
            return "XSS"
        else:
            return "REFLECTION"
    
    async def _test_reflection(self, session: aiohttp.ClientSession, url: str, param: str) -> Optional[Dict]:
        """Test single URL for payload reflection"""
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=False) as resp:
                # Check body
                body = await resp.text(errors='ignore')
                vuln_type = self._detect_vulnerability_type(body)
                if vuln_type:
                    return {
                        'url': url,
                        'param': param,
                        'type': 'body',
                        'vuln_type': vuln_type,
                        'status': resp.status
                    }
                
                # Check headers
                for header, value in resp.headers.items():
                    vuln_type = self._detect_vulnerability_type(value)
                    if vuln_type:
                        return {
                            'url': url,
                            'param': param,
                            'type': 'header',
                            'vuln_type': vuln_type,
                            'status': resp.status,
                            'header': header
                        }
                
                # Check redirect location
                location = resp.headers.get('location', '')
                if location:
                    vuln_type = self._detect_vulnerability_type(location)
                    if vuln_type:
                        return {
                            'url': url,
                            'param': param,
                            'type': 'redirect',
                            'vuln_type': vuln_type,
                            'status': resp.status,
                            'location': location
                        }
        
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        finally:
            self.completed_tests += 1
        
        return None
    
    def _print_progress(self):
        """Print scan progress"""
        if self.total_tests > 0:
            progress = (self.completed_tests / self.total_tests) * 100
            print(f"\r[*] Progress: {self.completed_tests}/{self.total_tests} ({progress:.1f}%)", end='', flush=True)
    
    async def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan list of URLs for reflections"""
        results = []
        found_params = set()
        
        # Build all test cases
        all_tests = []
        for url in urls:
            all_tests.extend(self._build_test_urls(url))
        
        self.total_tests = len(all_tests)
        self.completed_tests = 0
        
        if self.stats:
            self.stats.tests_performed = self.total_tests
        
        from utils.logger import get_logger
        logger = get_logger()
        logger.info(f"Testing {self.total_tests} parameter combinations")
        
        # Setup session
        connector = aiohttp.TCPConnector(limit_per_host=self.concurrency, ssl=False)
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=self.timeout, sock_read=self.timeout)
        headers = {"User-Agent": self.user_agent}
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
            sem = asyncio.Semaphore(self.concurrency)
            
            async def test_single(test_data):
                url, param = test_data
                
                # Create unique signature for URL + param combination
                parsed_url = urlparse(url)
                url_signature = f"{parsed_url.netloc}{parsed_url.path}:{param}"
                
                if url_signature in found_params:
                    self.completed_tests += 1
                    return
                
                async with sem:
                    result = await self._test_reflection(session, url, param)
                    if result:
                        found_params.add(url_signature)
                        results.append(result)
                        
                        # Use logger for vulnerability reporting
                        from utils.logger import get_logger
                        logger = get_logger()
                        
                        # Clear progress line and show result
                        print(f"\r{' ' * 50}\r", end='')
                        logger.vulnerability(result['vuln_type'], result['url'], result['param'])
                        self._print_progress()
                    else:
                        self._print_progress()
            
            # Process in batches to avoid task explosion
            batch_size = 100
            try:
                for i in range(0, len(all_tests), batch_size):
                    batch = all_tests[i:i + batch_size]
                    tasks = [asyncio.create_task(test_single(test)) for test in batch]
                    await asyncio.gather(*tasks)
                    
            except KeyboardInterrupt:
                print(f"\n[!] Scan interrupted by user")
                return results
        
        # Clear progress line and show completion
        print(f"\r{' ' * 50}\r", end='')
        from utils.logger import get_logger
        logger = get_logger()
        logger.success(f"Scan completed: {self.completed_tests}/{self.total_tests} tests finished")
        
        return results
