import aiohttp
import asyncio
import tempfile
import os
import base64
from pathlib import Path
from typing import List, Set
from .url_sources import URLSources
from config import API_KEY_SECRET

class URLCollector:
    def __init__(self, vt_api_key=None, intelx_api_key=None):
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        self.sources = URLSources()
        self.vt_api_key = vt_api_key
        self.intelx_api_key = intelx_api_key
        self.scanner_dir = None
        
        # Decode built-in API key
        try:
            self.secret_key = base64.b64decode(API_KEY_SECRET).decode()
        except:
            self.secret_key = None
    
    def _create_scanner_dir(self):
        """Create scanner directory for temp files"""
        scanner_path = Path("scanner")
        scanner_path.mkdir(exist_ok=True)
        self.scanner_dir = scanner_path
        return scanner_path
    
    async def collect_urls(self, domain: str) -> List[Path]:
        """Collect URLs from all sources and save to scanner folder"""
        print("[*] Collecting URLs from enhanced sources...")
        
        # Create scanner directory
        scanner_dir = self._create_scanner_dir()
        
        # Collect from different sources
        source_files = []
        
        tasks = [
            ("wayback", self.sources.fetch_wayback_cdx(domain)),
            ("commoncrawl", self.sources.fetch_commoncrawl(domain)),
            ("alienvault", self.sources.fetch_alienvault_enhanced(domain)),
            ("urlscan", self.sources.fetch_urlscan_enhanced(domain)),
            ("virustotal", self.sources.fetch_virustotal(domain, self.vt_api_key)),
            ("intelx", self.sources.fetch_intelx(domain, self.intelx_api_key)),
            ("crtsh", self.sources.fetch_crtsh_enhanced(domain)),
            ("webcrawler", self.sources.fetch_web_crawler(domain)),
            ("generated", self._generate_common_endpoints(domain))
        ]
        
        try:
            # Use shorter timeout for the entire collection process
            results = await asyncio.wait_for(
                asyncio.gather(*[task[1] for task in tasks], return_exceptions=True),
                timeout=180  # 3 minute timeout instead of 5
            )
            
            # Save each source to separate file
            for i, (source_name, result) in enumerate(zip([t[0] for t in tasks], results)):
                if isinstance(result, set) and result:
                    source_file = scanner_dir / f"{source_name}_urls.txt"
                    try:
                        with open(source_file, 'w') as f:
                            for url in sorted(result):
                                f.write(url + '\n')
                        source_files.append(source_file)
                        print(f"[*] {source_name.title()}: {len(result):,} URLs -> {source_file.name}")
                    except Exception as e:
                        print(f"[!] Failed to save {source_name}: {str(e)[:30]}")
                elif isinstance(result, Exception):
                    print(f"[!] {source_name.title()} failed: {str(result)[:50]}")
                elif isinstance(result, set) and not result:
                    print(f"[*] {source_name.title()}: 0 URLs (no results)")
        
        except asyncio.TimeoutError:
            print("[!] URL collection timeout (3min), using partial results")
        except KeyboardInterrupt:
            print("[!] URL collection interrupted")
            raise
        except Exception as e:
            print(f"[!] URL collection error: {str(e)[:50]}")
        finally:
            # Always close sources session
            try:
                await self.sources.close()
            except Exception:
                pass
        
        return source_files
    
    async def _generate_common_endpoints(self, domain: str) -> Set[str]:
        """Generate common endpoints with parameters"""
        urls = set()
        
        # Common parameter patterns
        patterns = [
            '/search?q=test', '/login?redirect=/', '/admin?page=1',
            '/api/users?id=1', '/user.php?id=1', '/search.php?s=test',
            '/page.php?p=1', '/view.php?file=test', '/redirect.php?url=test'
        ]
        
        subdomains = ['', 'www.', 'api.', 'admin.', 'app.']
        
        for subdomain in subdomains:
            for pattern in patterns:
                urls.add(f"https://{subdomain}{domain}{pattern}")
        
        return urls
