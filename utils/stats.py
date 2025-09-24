import time
from datetime import datetime, timedelta
from typing import Dict, List
from collections import Counter

class ScanStatistics:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.urls_collected = 0
        self.urls_filtered = 0
        self.tests_performed = 0
        self.vulnerabilities_found = 0
        self.sources_used = []
        self.vulnerability_types = Counter()
        self.parameter_types = Counter()
        self.status_codes = Counter()
        
    def start_scan(self):
        """Mark scan start time"""
        self.start_time = time.time()
    
    def end_scan(self):
        """Mark scan end time"""
        self.end_time = time.time()
    
    def add_source(self, source_name, url_count):
        """Add URL source statistics"""
        self.sources_used.append({
            'name': source_name,
            'urls': url_count
        })
        self.urls_collected += url_count
    
    def add_vulnerability(self, vuln_type, param, status_code=None):
        """Add vulnerability statistics"""
        self.vulnerabilities_found += 1
        self.vulnerability_types[vuln_type] += 1
        self.parameter_types[param] += 1
        if status_code:
            self.status_codes[status_code] += 1
    
    def get_duration(self):
        """Get scan duration"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0
    
    def get_rate(self):
        """Get tests per second rate"""
        duration = self.get_duration()
        if duration > 0:
            return self.tests_performed / duration
        return 0
    
    def generate_report(self) -> Dict:
        """Generate comprehensive statistics report"""
        duration = self.get_duration()
        
        return {
            'scan_info': {
                'start_time': datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S') if self.start_time else None,
                'end_time': datetime.fromtimestamp(self.end_time).strftime('%Y-%m-%d %H:%M:%S') if self.end_time else None,
                'duration': f"{duration:.2f} seconds" if duration > 0 else "0 seconds",
                'rate': f"{self.get_rate():.2f} tests/sec" if self.get_rate() > 0 else "0 tests/sec"
            },
            'url_collection': {
                'total_collected': self.urls_collected,
                'filtered_parameterized': self.urls_filtered,
                'sources': self.sources_used
            },
            'testing': {
                'total_tests': self.tests_performed,
                'vulnerabilities_found': self.vulnerabilities_found,
                'success_rate': f"{(self.vulnerabilities_found / max(self.tests_performed, 1)) * 100:.2f}%"
            },
            'vulnerabilities': {
                'by_type': dict(self.vulnerability_types),
                'by_parameter': dict(self.parameter_types.most_common(10)),
                'status_codes': dict(self.status_codes)
            }
        }
    
    def print_summary(self):
        """Print formatted summary"""
        from utils.logger import get_logger
        logger = get_logger()
        
        duration = self.get_duration()
        rate = self.get_rate()
        
        print("\n" + "="*70)
        print(f"{'SCAN SUMMARY':^70}")
        print("="*70)
        
        # Time info
        if duration > 0:
            duration_str = str(timedelta(seconds=int(duration)))
            logger.info(f"Scan Duration: {duration_str}")
            logger.info(f"Test Rate: {rate:.2f} tests/second")
        
        # Collection info
        logger.info(f"URLs Collected: {self.urls_collected:,}")
        logger.info(f"Parameterized URLs: {self.urls_filtered:,}")
        logger.info(f"Tests Performed: {self.tests_performed:,}")
        
        # Results
        if self.vulnerabilities_found > 0:
            logger.success(f"Vulnerabilities Found: {self.vulnerabilities_found}")
            
            # Vulnerability breakdown
            if self.vulnerability_types:
                print("\nVulnerability Types:")
                for vuln_type, count in self.vulnerability_types.most_common():
                    print(f"  {vuln_type}: {count}")
            
            # Top parameters
            if self.parameter_types:
                print("\nTop Vulnerable Parameters:")
                for param, count in self.parameter_types.most_common(5):
                    print(f"  {param}: {count}")
        else:
            logger.info("No vulnerabilities found")
        
        # Source breakdown
        if self.sources_used:
            print("\nURL Sources:")
            for source in self.sources_used:
                if source['urls'] > 0:
                    print(f"  {source['name']}: {source['urls']:,} URLs")
        
        print("="*70)
