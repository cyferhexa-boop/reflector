import aiohttp
import tempfile
import os
from typing import List

class WaybackFetcher:
    def __init__(self):
        self.wayback_url = "https://web.archive.org/cdx/search/cdx"
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    
    async def fetch_urls(self, domain: str) -> str:
        """Fetch URLs from Wayback Machine and save to temp file"""
        params = {
            "url": f"*.{domain}/*",
            "collapse": "urlkey",
            "output": "text", 
            "fl": "original",
        }
        
        # Create temp file
        temp_fd, temp_path = tempfile.mkstemp(suffix='.txt', prefix='wayback_')
        
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            headers = {"User-Agent": self.user_agent}
            
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(self.wayback_url, params=params) as resp:
                    if resp.status != 200:
                        raise Exception(f"Wayback returned status {resp.status}")
                    
                    content = await resp.text()
                    
                    # Write to temp file
                    with os.fdopen(temp_fd, 'w') as f:
                        f.write(content)
                    
                    print(f"[*] Fetched {len(content.splitlines())} URLs from Wayback")
                    return temp_path
                    
        except Exception as e:
            # Clean up on error
            try:
                os.close(temp_fd)
                os.unlink(temp_path)
            except:
                pass
            raise Exception(f"Failed to fetch Wayback URLs: {e}")
