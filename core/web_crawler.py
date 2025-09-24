import aiohttp
import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List
from bs4 import BeautifulSoup

class WebCrawler:
    def __init__(self, max_depth=2, max_threads=8, timeout=30, include_subs=False):
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.timeout = timeout
        self.include_subs = include_subs
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        self.visited = set()
        self.found_urls = set()
        
    def _is_valid_url(self, url: str, base_domain: str) -> bool:
        """Check if URL is valid and in scope"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False
            
            if self.include_subs:
                return base_domain in parsed.netloc
            else:
                return parsed.netloc == base_domain
        except:
            return False
    
    def _has_parameters(self, url: str) -> bool:
        """Check if URL has query parameters"""
        return '?' in url and '=' in url
    
    def _extract_urls_from_html(self, html: str, base_url: str, base_domain: str) -> Set[str]:
        """Extract URLs from HTML content"""
        urls = set()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract href attributes from <a> tags
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(base_url, href)
                if self._is_valid_url(absolute_url, base_domain) and self._has_parameters(absolute_url):
                    urls.add(absolute_url)
            
            # Extract src attributes from <script> tags
            for script in soup.find_all('script', src=True):
                src = script['src']
                absolute_url = urljoin(base_url, src)
                if self._is_valid_url(absolute_url, base_domain) and self._has_parameters(absolute_url):
                    urls.add(absolute_url)
            
            # Extract action attributes from <form> tags
            for form in soup.find_all('form', action=True):
                action = form['action']
                absolute_url = urljoin(base_url, action)
                if self._is_valid_url(absolute_url, base_domain) and self._has_parameters(absolute_url):
                    urls.add(absolute_url)
            
            # Extract URLs from JavaScript (basic patterns)
            js_url_patterns = [
                r'["\']https?://[^"\']*\?[^"\']*=[^"\']*["\']',
                r'["\'][^"\']*\?[^"\']*=[^"\']*["\']'
            ]
            
            for script in soup.find_all('script'):
                if script.string:
                    for pattern in js_url_patterns:
                        matches = re.findall(pattern, script.string)
                        for match in matches:
                            clean_url = match.strip('"\'')
                            if not clean_url.startswith('http'):
                                clean_url = urljoin(base_url, clean_url)
                            if self._is_valid_url(clean_url, base_domain) and self._has_parameters(clean_url):
                                urls.add(clean_url)
        
        except Exception as e:
            print(f"[!] HTML parsing error: {e}")
        
        return urls
    
    async def _crawl_url(self, session: aiohttp.ClientSession, url: str, base_domain: str, depth: int) -> Set[str]:
        """Crawl a single URL and extract parameter URLs"""
        if depth > self.max_depth or url in self.visited:
            return set()
        
        self.visited.add(url)
        urls = set()
        
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
                if resp.status == 200 and 'text/html' in resp.headers.get('content-type', ''):
                    html = await resp.text()
                    
                    # Extract URLs from this page
                    page_urls = self._extract_urls_from_html(html, url, base_domain)
                    urls.update(page_urls)
                    
                    # If not at max depth, crawl found links
                    if depth < self.max_depth:
                        # Get non-parameter URLs for further crawling
                        crawl_urls = set()
                        soup = BeautifulSoup(html, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            absolute_url = urljoin(url, href)
                            if (self._is_valid_url(absolute_url, base_domain) and 
                                absolute_url not in self.visited and 
                                len(crawl_urls) < 10):  # Limit to 10 links per page
                                crawl_urls.add(absolute_url)
                        
                        # Crawl found links
                        for crawl_url in crawl_urls:
                            sub_urls = await self._crawl_url(session, crawl_url, base_domain, depth + 1)
                            urls.update(sub_urls)
        
        except Exception as e:
            print(f"[!] Crawl error for {url}: {e}")
        
        return urls
    
    async def crawl_domain(self, start_urls: List[str]) -> Set[str]:
        """Crawl domain starting from given URLs"""
        all_urls = set()
        
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=self.max_threads)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {"User-Agent": self.user_agent}
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
            sem = asyncio.Semaphore(self.max_threads)
            
            async def crawl_with_semaphore(url):
                async with sem:
                    try:
                        parsed = urlparse(url)
                        base_domain = parsed.netloc
                        return await self._crawl_url(session, url, base_domain, 0)
                    except Exception as e:
                        print(f"[!] Failed to crawl {url}: {e}")
                        return set()
            
            # Crawl all start URLs concurrently
            tasks = [crawl_with_semaphore(url) for url in start_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, set):
                    all_urls.update(result)
        
        return all_urls
    
    async def crawl_from_domain(self, domain: str) -> Set[str]:
        """Crawl domain starting from common entry points with better error handling"""
        start_urls = [
            f"https://{domain}",
            f"https://www.{domain}",
            f"http://{domain}",
            f"http://www.{domain}"
        ]
        
        # Test which URLs are accessible with shorter timeout
        accessible_urls = []
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            timeout = aiohttp.ClientTimeout(total=8, sock_connect=3)
            headers = {"User-Agent": self.user_agent}
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
                for url in start_urls:
                    try:
                        async with session.head(url, allow_redirects=True) as resp:
                            if resp.status < 400:
                                accessible_urls.append(str(resp.url))
                                break  # Use first accessible URL
                    except asyncio.TimeoutError:
                        print(f"[!] Timeout testing {url}")
                        continue
                    except Exception:
                        continue
        except Exception as e:
            print(f"[!] Web crawler setup failed: {str(e)[:30]}")
        
        if not accessible_urls:
            print(f"[!] No accessible entry points found for {domain}")
            return set()
        
        print(f"[*] Web crawling starting from: {accessible_urls[0]}")
        
        try:
            return await self.crawl_domain(accessible_urls)
        except Exception as e:
            print(f"[!] Web crawling failed: {str(e)[:50]}")
            return set()
