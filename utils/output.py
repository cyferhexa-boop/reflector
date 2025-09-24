import json
import csv
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse
from config import COLORS, MAX_RESULTS_DISPLAY

class OutputHandler:
    def __init__(self):
        self.reset = COLORS['RESET']
    
    def display_results(self, results: List[Dict], show_all=False):
        """Display results in professional format"""
        if not results:
            print(f"\n{COLORS['INFO']}[*]{self.reset} No vulnerabilities found")
            return
        
        # Group by vulnerability type
        vuln_groups = {}
        for result in results:
            vuln_type = result.get('vuln_type', 'UNKNOWN')
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(result)
        
        print(f"\n{COLORS['SUCCESS']}[+]{self.reset} Found {len(results)} vulnerabilities")
        print("="*80)
        
        total_displayed = 0
        
        for vuln_type, vulns in vuln_groups.items():
            # Enhanced color display for XSS+SQL
            if vuln_type == 'XSS+SQL':
                color_display = f"{COLORS['WARNING']}XSS{COLORS['RESET']}+{COLORS['ERROR']}SQL{COLORS['RESET']}"
            else:
                color_map = {
                    'SQL': COLORS['ERROR'],      # Red
                    'XSS': COLORS['WARNING'],    # Yellow
                    'REFLECTION': COLORS['INFO'] # Blue
                }
                color = color_map.get(vuln_type, COLORS['SUCCESS'])
                color_display = f"{color}{vuln_type}{COLORS['RESET']}"
            
            print(f"\n[{color_display}] - {len(vulns)} found")
            print("-"*60)
            
            # Show limited results unless show_all is True
            display_count = len(vulns) if show_all else min(len(vulns), MAX_RESULTS_DISPLAY // len(vuln_groups))
            
            for i, result in enumerate(vulns[:display_count]):
                parsed = urlparse(result['url'])
                domain = parsed.netloc
                path = parsed.path or '/'
                
                reflection_type = result['type']
                if reflection_type == 'header' and 'header' in result:
                    reflection_type = f"header:{result['header']}"
                
                print(f"{i+1:2d}. Parameter: {COLORS['WARNING']}{result['param']}{self.reset}")
                print(f"    Domain:    {domain}")
                print(f"    Path:      {path}")
                print(f"    Location:  {reflection_type}")
                print(f"    Status:    {result.get('status', 'N/A')}")
                print(f"    URL:       {result['url']}")
                print()
                
                total_displayed += 1
            
            # Show truncation message if needed
            if not show_all and len(vulns) > display_count:
                remaining = len(vulns) - display_count
                print(f"    ... and {remaining} more {vuln_type} vulnerabilities")
                print(f"    Use --show-all to display all results")
                print()
        
        print("="*80)
    
    def save_results(self, results: List[Dict], output_file: str, format_type='json'):
        """Save results in specified format"""
        try:
            if format_type.lower() == 'json':
                self._save_json(results, output_file)
            elif format_type.lower() == 'csv':
                self._save_csv(results, output_file)
            elif format_type.lower() == 'txt':
                self._save_txt(results, output_file)
            else:
                self._save_json(results, output_file)
            
            print(f"\n{COLORS['SUCCESS']}[+]{self.reset} Results saved to: {output_file}")
            
        except Exception as e:
            print(f"\n{COLORS['ERROR']}[!]{self.reset} Failed to save results: {e}")
    
    def _save_json(self, results: List[Dict], output_file: str):
        """Save as JSON with metadata"""
        output_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(results),
                'tool': 'Reflector v1.0.0',
                'author': 'NRS'
            },
            'vulnerabilities': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
    
    def _save_csv(self, results: List[Dict], output_file: str):
        """Save as CSV"""
        if not results:
            return
        
        fieldnames = ['vuln_type', 'param', 'url', 'type', 'status', 'domain', 'path']
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                parsed = urlparse(result['url'])
                row = {
                    'vuln_type': result.get('vuln_type', 'UNKNOWN'),
                    'param': result['param'],
                    'url': result['url'],
                    'type': result['type'],
                    'status': result.get('status', ''),
                    'domain': parsed.netloc,
                    'path': parsed.path or '/'
                }
                writer.writerow(row)
    
    def _save_txt(self, results: List[Dict], output_file: str):
        """Save as plain text"""
        with open(output_file, 'w') as f:
            f.write(f"Reflector v1.0.0 - Vulnerability Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Vulnerabilities: {len(results)}\n")
            f.write("="*80 + "\n\n")
            
            # Group by type
            vuln_groups = {}
            for result in results:
                vuln_type = result.get('vuln_type', 'UNKNOWN')
                if vuln_type not in vuln_groups:
                    vuln_groups[vuln_type] = []
                vuln_groups[vuln_type].append(result)
            
            for vuln_type, vulns in vuln_groups.items():
                f.write(f"[{vuln_type}] - {len(vulns)} found\n")
                f.write("-"*60 + "\n")
                
                for i, result in enumerate(vulns, 1):
                    parsed = urlparse(result['url'])
                    f.write(f"{i:2d}. Parameter: {result['param']}\n")
                    f.write(f"    Domain:    {parsed.netloc}\n")
                    f.write(f"    Path:      {parsed.path or '/'}\n")
                    f.write(f"    Location:  {result['type']}\n")
                    f.write(f"    Status:    {result.get('status', 'N/A')}\n")
                    f.write(f"    URL:       {result['url']}\n\n")
                
                f.write("\n")
    
    def get_summary(self, results: List[Dict]) -> Dict:
        """Get summary statistics"""
        if not results:
            return {"total": 0, "by_type": {}, "by_param": {}, "by_vuln": {}}
        
        by_type = {}
        by_param = {}
        by_vuln = {}
        by_domain = {}
        
        for result in results:
            # Count by reflection type
            ref_type = result['type']
            by_type[ref_type] = by_type.get(ref_type, 0) + 1
            
            # Count by parameter name
            param = result['param']
            by_param[param] = by_param.get(param, 0) + 1
            
            # Count by vulnerability type
            vuln_type = result.get('vuln_type', 'UNKNOWN')
            by_vuln[vuln_type] = by_vuln.get(vuln_type, 0) + 1
            
            # Count by domain
            domain = urlparse(result['url']).netloc
            by_domain[domain] = by_domain.get(domain, 0) + 1
        
        return {
            "total": len(results),
            "by_type": by_type,
            "by_param": by_param,
            "by_vuln": by_vuln,
            "by_domain": by_domain
        }
