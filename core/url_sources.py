import aiohttp
import asyncio
import json
from typing import Set, List
from urllib.parse import urlparse
from config import *
from .web_crawler import WebCrawler

class URLSources:
    def __init__(self):
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        self.session = None
    
    async def _get_session(self):
        if not self.session or self.session.closed:
            try:
                timeout = aiohttp.ClientTimeout(total=30, sock_connect=10, sock_read=20)
                headers = {"User-Agent": self.user_agent}
                connector = aiohttp.TCPConnector(
                    ssl=False, 
                    limit=50, 
                    limit_per_host=10,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    keepalive_timeout=30
                )
                self.session = aiohttp.ClientSession(
                    timeout=timeout, 
                    headers=headers, 
                    connector=connector,
                    raise_for_status=False
                )
            except Exception as e:
                print(f"[!] Session creation failed: {e}")
                # Create minimal session as fallback
                self.session = aiohttp.ClientSession()
        return self.session
    
    async def fetch_wayback_cdx(self, domain: str) -> Set[str]:
        """Fetch URLs from Wayback CDX API with multiple fallbacks"""
        urls = set()
        
        # Try multiple Wayback endpoints with better error handling
        wayback_endpoints = [
            "https://web.archive.org/cdx/search/cdx",
            "http://web.archive.org/cdx/search/cdx",
            "https://archive.org/wayback/available"
        ]
        
        for endpoint in wayback_endpoints:
            try:
                session = await self._get_session()
                
                if "available" in endpoint:
                    # Alternative endpoint format
                    test_url = f"https://{domain}"
                    async with session.get(f"{endpoint}?url={test_url}", timeout=15) as resp:
                        if resp.status == 200:
                            # This is just a connectivity test, skip actual processing
                            continue
                else:
                    # Standard CDX format
                    params = {
                        'url': f'*.{domain}/*',
                        'output': 'text',
                        'fl': 'original',
                        'collapse': 'urlkey',
                        'limit': 10000  # Restored higher limit
                    }
                    
                    async with session.get(endpoint, params=params, timeout=20) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            for line in text.splitlines():  # Process all lines
                                if line.strip() and '?' in line and '=' in line:
                                    urls.add(line.strip())
                            
                            if urls:  # Success, break out
                                break
                                
            except asyncio.TimeoutError:
                print(f"[!] Wayback timeout: {endpoint}")
                continue
            except Exception as e:
                print(f"[!] Wayback endpoint {endpoint} failed: {str(e)[:50]}")
                continue
        
        # If all Wayback methods fail, return empty set (don't crash)
        return urls

    async def fetch_commoncrawl(self, domain: str) -> Set[str]:
        """Fetch URLs from Common Crawl using latest index with better error handling"""
        urls = set()
        try:
            session = await self._get_session()
            
            # Get latest Common Crawl index with timeout
            async with session.get(CCRAWL_INDEX_URL, timeout=15) as resp:
                if resp.status == 200:
                    indexes = await resp.json()
                    
                    if indexes and len(indexes) > 0:
                        # Try latest index first, then fallback to older ones
                        for i in range(min(3, len(indexes))):  # Try up to 3 indexes
                            try:
                                index_info = indexes[i]
                                if 'cdx-api' not in index_info:
                                    continue
                                    
                                latest_index = index_info['cdx-api']
                                params = {
                                    'url': f'*.{domain}/*',
                                    'output': 'json',
                                    'collapse': 'urlkey',
                                    'limit': 10000  # Restored higher limit
                                }
                                
                                async with session.get(latest_index, params=params, timeout=25) as cc_resp:
                                    if cc_resp.status == 200:
                                        text = await cc_resp.text()
                                        for line in text.splitlines():  # Process all lines
                                            if line.strip():
                                                try:
                                                    data = json.loads(line)
                                                    if len(data) > 2 and '?' in data[2] and '=' in data[2]:
                                                        urls.add(data[2])
                                                except:
                                                    continue
                                        
                                        if urls:  # Success with this index
                                            break
                                            
                            except asyncio.TimeoutError:
                                print(f"[!] Common Crawl index {i} timeout")
                                continue
                            except Exception as e:
                                print(f"[!] Common Crawl index {i} failed: {str(e)[:30]}")
                                continue
                                
        except asyncio.TimeoutError:
            print("[!] Common Crawl index list timeout")
        except Exception as e:
            print(f"[!] Common Crawl failed: {str(e)[:30]}")
        
        return urls
    
    async def fetch_alienvault_enhanced(self, domain: str) -> Set[str]:
        """Fetch URLs from AlienVault OTX with enhanced parameters"""
        urls = set()
        try:
            session = await self._get_session()
            
            # Try different indicator types
            types = ['domain', 'hostname']
            
            for indicator_type in types:
                url = ALIENVAULT_URL.format(TYPE=indicator_type, DOMAIN=domain)
                
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if 'url_list' in data:
                            for item in data['url_list']:
                                if 'url' in item:
                                    urls.add(item['url'])
                        
                        # Also check for passive DNS data
                        if 'passive_dns' in data:
                            for dns_item in data['passive_dns']:
                                if 'hostname' in dns_item:
                                    hostname = dns_item['hostname']
                                    urls.add(f"https://{hostname}")
                                    urls.add(f"http://{hostname}")
                
                await asyncio.sleep(1)  # Rate limiting
                
        except Exception as e:
            print(f"[!] AlienVault OTX enhanced failed: {e}")
        
        return urls
    
    async def fetch_urlscan_enhanced(self, domain: str) -> Set[str]:
        """Fetch URLs from URLScan.io with date ranges"""
        urls = set()
        try:
            session = await self._get_session()
            
            # Try different date ranges for more comprehensive results
            date_ranges = [
                '',  # All time
                ' after:2023-01-01',  # Recent
                ' after:2022-01-01 before:2023-01-01'  # Previous year
            ]
            
            for date_range in date_ranges:
                url = URLSCAN_URL.format(DOMAIN=domain, DATERANGE=date_range)
                
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if 'results' in data:
                            for result in data['results']:
                                # Get page URL
                                if 'page' in result and 'url' in result['page']:
                                    urls.add(result['page']['url'])
                                
                                # Get task URL
                                if 'task' in result and 'url' in result['task']:
                                    urls.add(result['task']['url'])
                                
                                # Get DOM URLs if available
                                if 'task' in result and 'uuid' in result['task']:
                                    uuid = result['task']['uuid']
                                    dom_url = f"{URLSCAN_DOM_URL}{uuid}/"
                                    
                                    try:
                                        async with session.get(dom_url) as dom_resp:
                                            if dom_resp.status == 200:
                                                dom_text = await dom_resp.text()
                                                # Extract URLs from DOM
                                                import re
                                                url_pattern = rf'https?://{re.escape(domain)}[^\s\'"<>]+'
                                                dom_urls = re.findall(url_pattern, dom_text)
                                                urls.update(dom_urls)
                                    except:
                                        pass
                
                await asyncio.sleep(2)  # Rate limiting
                
        except Exception as e:
            print(f"[!] URLScan.io enhanced failed: {e}")
        
        return urls
    
    async def fetch_virustotal(self, domain: str, api_key: str = None) -> Set[str]:
        """Fetch URLs from VirusTotal (requires API key for full access)"""
        urls = set()
        try:
            session = await self._get_session()
            
            if api_key:
                url = VIRUSTOTAL_URL.format(APIKEY=api_key, DOMAIN=domain)
            else:
                # Try public endpoint (limited)
                url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Extract detected URLs
                    if 'detected_urls' in data:
                        for item in data['detected_urls']:
                            if 'url' in item:
                                urls.add(item['url'])
                    
                    # Extract undetected URLs
                    if 'undetected_urls' in data:
                        for item in data['undetected_urls']:
                            if isinstance(item, list) and len(item) > 0:
                                urls.add(item[0])
                            elif isinstance(item, dict) and 'url' in item:
                                urls.add(item['url'])
                                
        except Exception as e:
            print(f"[!] VirusTotal failed: {e}")
        
        return urls
    
    async def fetch_intelx(self, domain: str, api_key: str = None) -> Set[str]:
        """Fetch URLs from Intelligence X"""
        urls = set()
        try:
            session = await self._get_session()
            
            # Search request
            search_data = {
                'term': domain,
                'buckets': [],
                'lookuplevel': 0,
                'maxresults': 10000,
                'timeout': 0,
                'datefrom': '',
                'dateto': '',
                'sort': 4,
                'media': 0,
                'terminate': []
            }
            
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['x-key'] = api_key
            
            async with session.post(INTELX_SEARCH_URL, json=search_data, headers=headers) as resp:
                if resp.status == 200:
                    search_result = await resp.json()
                    
                    if 'id' in search_result:
                        search_id = search_result['id']
                        
                        # Wait for results
                        await asyncio.sleep(5)
                        
                        # Get results
                        results_url = f"{INTELX_RESULTS_URL}{search_id}"
                        async with session.get(results_url, headers=headers) as results_resp:
                            if results_resp.status == 200:
                                results_data = await results_resp.json()
                                
                                if 'records' in results_data:
                                    for record in results_data['records']:
                                        if 'name' in record:
                                            # Extract URLs from record names
                                            name = record['name']
                                            if name.startswith('http'):
                                                urls.add(name)
                                            elif domain in name:
                                                urls.add(f"https://{name}")
                                                
        except Exception as e:
            print(f"[!] Intelligence X failed: {e}")
        
        return urls
    
    async def fetch_crtsh_enhanced(self, domain: str) -> Set[str]:
        """Enhanced crt.sh with more endpoint generation"""
        urls = set()
        try:
            session = await self._get_session()
            crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with session.get(crt_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = set()
                    
                    for cert in data:
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if name.endswith(f'.{domain}') or name == domain:
                                    subdomains.add(name)
                    
                    # Enhanced path generation
                    common_paths = [
                        '/', '/search', '/login', '/admin', '/api', '/v1', '/v2', '/v3',
                        '/index.php', '/search.php', '/login.php', '/admin.php',
                        '/user.php', '/product.php', '/category.php', '/news.php',
                        '/api/v1/users', '/api/v2/search', '/api/users', '/api/search',
                        '/rest/api/search', '/graphql', '/oauth/authorize', '/sso/login',
                        '/callback', '/webhook', '/redirect', '/proxy', '/download'
                    ]
                    
                    # Add parameters to paths
                    param_paths = []
                    for path in common_paths:
                        if '?' not in path:
                            param_paths.extend([
                                f"{path}?id=1", f"{path}?q=test", f"{path}?search=test",
                                f"{path}?page=1", f"{path}?limit=10", f"{path}?format=json",
                                f"{path}?callback=test", f"{path}?redirect=/", f"{path}?url=test"
                            ])
                    
                    # Generate URLs for subdomains
                    for subdomain in list(subdomains)[:30]:  # Limit to 30 subdomains
                        for path in param_paths:
                            urls.add(f"https://{subdomain}{path}")
                            
        except Exception as e:
            print(f"[!] crt.sh enhanced failed: {e}")
        
        return urls
    
    async def fetch_web_crawler(self, domain: str) -> Set[str]:
        """Crawl domain like hakrawler to find parameter URLs"""
        urls = set()
        try:
            crawler = WebCrawler(
                max_depth=2,
                max_threads=8,
                timeout=30,
                include_subs=True
            )
            
            crawled_urls = await crawler.crawl_from_domain(domain)
            urls.update(crawled_urls)
            
        except Exception as e:
            print(f"[!] Web crawler failed: {e}")
        
        return urls

    async def close(self):
        if self.session and not self.session.closed:
            try:
                await self.session.close()
                # Wait for underlying connections to close
                await asyncio.sleep(0.1)
            except Exception:
                pass
            finally:
                self.session = None
