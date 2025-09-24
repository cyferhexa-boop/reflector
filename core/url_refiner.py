import aiohttp
import asyncio
import os
from pathlib import Path
from typing import List, Set
from urllib.parse import urlparse

class URLRefiner:
    def __init__(self, concurrency=100, timeout=3, skip_reachability=False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.skip_reachability = skip_reachability
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    
    def _has_parameters(self, url: str) -> bool:
        """Check if URL has query parameters"""
        return '?' in url and '=' in url
    
    def _deduplicate_urls(self, source_files: List[Path]) -> Set[str]:
        """Read all source files and deduplicate URLs more effectively"""
        all_urls = set()
        seen_signatures = set()
        
        for file_path in source_files:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and self._has_parameters(url):
                            # Create signature: domain + path + sorted param names (ignore values)
                            try:
                                from urllib.parse import urlparse, parse_qs
                                parsed = urlparse(url)
                                params = parse_qs(parsed.query)
                                if params:
                                    param_names = '+'.join(sorted(params.keys()))
                                    signature = f"{parsed.netloc}{parsed.path}?{param_names}"
                                    
                                    if signature not in seen_signatures:
                                        seen_signatures.add(signature)
                                        all_urls.add(url)
                            except:
                                # Fallback: add URL as-is if parsing fails
                                all_urls.add(url)
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")
        
        return all_urls
    
    async def _quick_check_url(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Quick HEAD request to check if URL exists"""
        try:
            async with session.head(url, timeout=self.timeout, allow_redirects=False) as resp:
                return resp.status < 500  # Accept anything except server errors
        except:
            return True  # If can't check, assume it's reachable
    
    async def _filter_reachable_urls(self, urls: Set[str]) -> Set[str]:
        """Fast filter for obviously unreachable URLs"""
        if self.skip_reachability:
            print("[*] Skipping reachability check (fast mode)")
            return urls
        
        print(f"[*] Quick reachability check of {len(urls):,} URLs...")
        
        reachable_urls = set()
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=self.concurrency, limit=self.concurrency*2)
        timeout = aiohttp.ClientTimeout(total=self.timeout, sock_connect=1, sock_read=1)
        headers = {"User-Agent": self.user_agent}
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
            sem = asyncio.Semaphore(self.concurrency)
            
            async def check_single(url):
                async with sem:
                    if await self._quick_check_url(session, url):
                        reachable_urls.add(url)
            
            # Process all URLs concurrently with batching
            batch_size = 500
            url_list = list(urls)
            
            for i in range(0, len(url_list), batch_size):
                batch = url_list[i:i + batch_size]
                tasks = [asyncio.create_task(check_single(url)) for url in batch]
                
                try:
                    await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=30)
                    progress = min(i + batch_size, len(url_list))
                    print(f"\r[*] Checked: {progress}/{len(url_list)} ({(progress/len(url_list)*100):.1f}%)", end='', flush=True)
                except asyncio.TimeoutError:
                    print(f"\n[!] Batch timeout, continuing...")
                    break
                except KeyboardInterrupt:
                    print(f"\n[!] Reachability check interrupted")
                    break
        
        print(f"\n[*] Found {len(reachable_urls):,} reachable URLs")
        return reachable_urls if reachable_urls else urls  # Fallback to all URLs if check failed
    
    async def refine_urls(self, source_files: List[Path], fast_mode=False) -> str:
        """Refine URLs: deduplicate and optionally filter unreachable ones"""
        print("[*] Starting URL refinement process...")
        
        # Step 1: Deduplicate
        print("[*] Deduplicating URLs...")
        unique_urls = self._deduplicate_urls(source_files)
        print(f"[*] Deduplicated to {len(unique_urls):,} unique parameterized URLs")
        
        # Step 2: Optional reachability check
        if fast_mode or self.skip_reachability:
            refined_urls = unique_urls
            print("[*] Skipping reachability check for faster processing")
        else:
            refined_urls = await self._filter_reachable_urls(unique_urls)
        
        # Step 3: Save refined URLs
        scanner_dir = Path("scanner")
        refined_file = scanner_dir / "refine-url.txt"
        
        with open(refined_file, 'w') as f:
            for url in sorted(refined_urls):
                f.write(url + '\n')
        
        print(f"[*] Saved {len(refined_urls):,} refined URLs to {refined_file}")
        
        # Step 4: Clean up source files
        self._cleanup_source_files(source_files)
        
        return str(refined_file)
    
    def _cleanup_source_files(self, source_files: List[Path]):
        """Delete all source files but keep refine-url.txt"""
        cleaned = 0
        for file_path in source_files:
            try:
                if file_path.exists() and file_path.name != "refine-url.txt":
                    file_path.unlink()
                    cleaned += 1
            except Exception as e:
                print(f"[!] Failed to cleanup {file_path}: {e}")
        
        if cleaned > 0:
            print(f"[*] Cleaned up {cleaned} source files")
