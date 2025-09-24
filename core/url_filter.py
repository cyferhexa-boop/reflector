from urllib.parse import urlparse, parse_qs
from typing import List, Set

class URLFilter:
    def __init__(self):
        pass
    
    def _normalize_url(self, url: str) -> str:
        """Add https if no scheme present"""
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url.lstrip('/')
        return url
    
    def _has_parameters(self, url: str) -> bool:
        """Check if URL has query parameters"""
        return '?' in url and '=' in url
    
    def _create_signature(self, url: str) -> str:
        """Create unique signature for URL deduplication"""
        try:
            parsed = urlparse(self._normalize_url(url))
            params = parse_qs(parsed.query)
            if not params:
                return None
            
            # Create signature: domain + path + sorted param names
            param_names = '+'.join(sorted(params.keys()))
            return f"{parsed.netloc}{parsed.path}?{param_names}"
        except:
            return None
    
    def filter_param_urls(self, source: str) -> List[str]:
        """Filter and deduplicate parameterized URLs from file or list"""
        urls = []
        
        # Read URLs from file
        try:
            with open(source, 'r') as f:
                lines = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {source}")
            return []
        
        # Filter and deduplicate
        seen_signatures = set()
        
        for line in lines:
            if not self._has_parameters(line):
                continue
            
            signature = self._create_signature(line)
            if signature and signature not in seen_signatures:
                seen_signatures.add(signature)
                urls.append(line.strip())
        
        return urls
    
    def filter_from_list(self, url_list: List[str]) -> List[str]:
        """Filter parameterized URLs from a list"""
        seen_signatures = set()
        filtered = []
        
        for url in url_list:
            if not self._has_parameters(url):
                continue
            
            signature = self._create_signature(url)
            if signature and signature not in seen_signatures:
                seen_signatures.add(signature)
                filtered.append(url)
        
        return filtered
