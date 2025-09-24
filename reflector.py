#!/usr/bin/env python3

import argparse
import asyncio
import sys
import os
import tempfile
import signal
import atexit
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config import VERSION, AUTHOR, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT, DEFAULT_PAYLOAD, MAX_CONCURRENCY, MIN_TIMEOUT, MAX_TIMEOUT
from core.wayback_fetcher import WaybackFetcher
from core.url_collector import URLCollector
from core.url_refiner import URLRefiner
from core.url_filter import URLFilter
from core.scanner import ReflectionScanner
from utils.output import OutputHandler
from utils.banner import show_banner
from utils.cleanup import cleanup_temp_files, cleanup_all_temp_data, emergency_cleanup
from utils.logger import ReflectorLogger
from utils.stats import ScanStatistics

# Global cleanup flag
cleanup_registered = False

def register_cleanup():
    """Register cleanup functions for proper shutdown"""
    global cleanup_registered
    if not cleanup_registered:
        atexit.register(emergency_cleanup)
        signal.signal(signal.SIGINT, lambda s, f: handle_interrupt())
        signal.signal(signal.SIGTERM, lambda s, f: handle_interrupt())
        cleanup_registered = True

def handle_interrupt():
    """Handle Ctrl+C interrupt"""
    print('\n[!] Interrupted by user')
    emergency_cleanup()
    sys.exit(0)

def show_help():
    help_text = f"""
Reflector v{VERSION} - Professional Parameter Reflection Scanner
Made by {AUTHOR}

USAGE:
    python3 reflector.py <domain> [options]
    python3 reflector.py -f <url_file> [options]

OPTIONS:
    -f, --file          File containing URLs to test
    -c, --concurrency   Number of concurrent workers (default: {DEFAULT_CONCURRENCY}, max: {MAX_CONCURRENCY})
    -p, --payload       Custom payload (default: {DEFAULT_PAYLOAD})
    -o, --output        Output file (supports .json, .csv, .txt)
    -t, --timeout       Request timeout in seconds (default: {DEFAULT_TIMEOUT})
    --vt-key            VirusTotal API key (for enhanced results)
    --intelx-key        Intelligence X API key (for enhanced results)
    --fast              Skip reachability check (much faster)
    --wayback-only      Only use Wayback Machine (faster)
    --show-all          Display all results (no truncation)
    --log-file          Save detailed logs to file
    --no-cleanup        Don't delete temporary files
    --verbose           Enable verbose logging
    -h, --help          Show this help menu

EXAMPLES:
    # Basic comprehensive scan
    python3 reflector.py example.com
    
    # Fast scan (skip reachability check)
    python3 reflector.py example.com --fast
    
    # Fastest scan (Wayback only)
    python3 reflector.py example.com --wayback-only
    
    # Enhanced scan with API keys
    python3 reflector.py target.com --vt-key YOUR_VT_KEY --intelx-key YOUR_IX_KEY
    
    # High-performance fast scan
    python3 reflector.py target.com --fast -c 100 -o results.json
    
    # Scan from custom URL file
    python3 reflector.py -f urls.txt --show-all
    
    # Custom payload testing
    python3 reflector.py site.com -p "<script>alert(1)</script>"

WORKFLOW:
    1. Collect URLs from multiple sources → scanner/ folder
    2. Deduplicate and filter unreachable URLs → refine-url.txt
    3. Scan refined URLs for reflections → results
    4. Auto-cleanup all temporary files

FEATURES:
    • Enhanced multi-source URL collection:
      - Wayback Machine & Common Crawl archives
      - URLScan.io with DOM analysis & date ranges
      - AlienVault OTX with passive DNS
      - VirusTotal (with API key support)
      - Intelligence X phonebook search
      - crt.sh certificate transparency logs
      - Live web crawler (hakrawler-style)
      - Smart endpoint generation (1000+ patterns)
    • Intelligent URL refinement (deduplication + reachability)
    • XSS and reflection vulnerability detection
    • Real-time progress tracking with statistics
    • Professional output formatting (JSON/CSV/TXT)
    • Comprehensive logging and error handling
    • Automatic cleanup and resource management
    • Production-ready performance optimization
    """
    print(help_text)

def validate_args(args):
    """Validate command line arguments"""
    errors = []
    
    if not args.domain and not args.file:
        errors.append("Either domain or --file must be specified")
    
    if args.concurrency < 1 or args.concurrency > MAX_CONCURRENCY:
        errors.append(f"Concurrency must be between 1 and {MAX_CONCURRENCY}")
    
    if args.timeout < MIN_TIMEOUT or args.timeout > MAX_TIMEOUT:
        errors.append(f"Timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")
    
    if args.file and not os.path.exists(args.file):
        errors.append(f"Input file not found: {args.file}")
    
    return errors

async def main():
    # Register cleanup handlers
    register_cleanup()
    
    # Clean up any existing temp data from previous runs
    cleanup_all_temp_data()
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('domain', nargs='?', help='Target domain')
    parser.add_argument('-f', '--file', help='File containing URLs')
    parser.add_argument('-c', '--concurrency', type=int, default=DEFAULT_CONCURRENCY, help='Concurrent workers')
    parser.add_argument('-p', '--payload', default=DEFAULT_PAYLOAD, help='Test payload')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, help='Request timeout')
    parser.add_argument('--vt-key', help='VirusTotal API key')
    parser.add_argument('--intelx-key', help='Intelligence X API key')
    parser.add_argument('--fast', action='store_true', help='Skip reachability check (faster)')
    parser.add_argument('--wayback-only', action='store_true', help='Only use Wayback Machine')
    parser.add_argument('--show-all', action='store_true', help='Display all results')
    parser.add_argument('--log-file', help='Log file path')
    parser.add_argument('--no-cleanup', action='store_true', help='Keep temp files')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    
    args = parser.parse_args()
    
    if args.help:
        show_help()
        return
    
    # Validate arguments
    validation_errors = validate_args(args)
    if validation_errors:
        print(f"Error: {'; '.join(validation_errors)}")
        show_help()
        return
    
    # Setup logging
    logger = ReflectorLogger(log_file=args.log_file, verbose=args.verbose)
    
    # Setup statistics
    stats = ScanStatistics()
    stats.start_scan()
    
    show_banner()
    
    temp_files = []
    results = []
    refined_file = None
    
    try:
        # Step 1: URL Collection to scanner/ folder
        if args.domain:
            if args.wayback_only:
                logger.info(f"Fetching Wayback URLs for: {args.domain}")
                fetcher = WaybackFetcher()
                temp_file = await fetcher.fetch_urls(args.domain)
                temp_files.append(temp_file)
                url_source = temp_file
                
                # Count URLs for stats
                try:
                    with open(temp_file, 'r') as f:
                        wayback_count = sum(1 for line in f if line.strip())
                    stats.add_source("Wayback Machine", wayback_count)
                except:
                    stats.add_source("Wayback Machine", 0)
            else:
                logger.info(f"Collecting URLs from multiple sources for: {args.domain}")
                
                # Collect URLs to scanner/ folder
                url_collector = URLCollector(
                    vt_api_key=args.vt_key,
                    intelx_api_key=args.intelx_key
                )
                source_files = await url_collector.collect_urls(args.domain)
                
                # Step 2: Refine URLs (deduplicate + filter unreachable)
                logger.info("Refining URLs (deduplication + reachability check)...")
                url_refiner = URLRefiner(
                    concurrency=min(args.concurrency*2, 200), 
                    timeout=3, 
                    skip_reachability=args.fast
                )
                refined_file = await url_refiner.refine_urls(source_files, fast_mode=args.fast)
                
                url_source = refined_file
                stats.add_source("All Sources (Refined)", 0)  # Will be updated below
        else:
            url_source = args.file
            try:
                with open(args.file, 'r') as f:
                    file_count = sum(1 for line in f if line.strip())
                stats.add_source("Input File", file_count)
            except:
                stats.add_source("Input File", 0)
        
        # Step 3: Filter parameterized URLs (if not already refined)
        if not refined_file:
            logger.info("Filtering parameterized URLs...")
            filter_handler = URLFilter()
            param_urls = filter_handler.filter_param_urls(url_source)
        else:
            # URLs are already refined and parameterized
            param_urls = []
            try:
                with open(refined_file, 'r') as f:
                    param_urls = [line.strip() for line in f if line.strip()]
            except:
                param_urls = []
        
        if not param_urls:
            logger.warning("No parameterized URLs found")
            return
        
        stats.urls_filtered = len(param_urls)
        logger.success(f"Found {len(param_urls):,} parameterized URLs ready for testing")
        
        # Step 4: Vulnerability scanning
        logger.info(f"Starting vulnerability scan with {args.concurrency} workers...")
        logger.info(f"Payload: {args.payload}")
        logger.info("Press Ctrl+C to stop\n")
        
        scanner = ReflectionScanner(
            concurrency=args.concurrency,
            payload=args.payload,
            timeout=args.timeout,
            stats=stats
        )
        
        results = await scanner.scan_urls(param_urls)
        
        # Update statistics
        for result in results:
            stats.add_vulnerability(
                result.get('vuln_type', 'UNKNOWN'),
                result['param'],
                result.get('status')
            )
        
        # Step 5: Output results
        output_handler = OutputHandler()
        output_handler.display_results(results, show_all=args.show_all)
        
        if args.output:
            # Determine format from extension
            if args.output.endswith('.csv'):
                format_type = 'csv'
            elif args.output.endswith('.txt'):
                format_type = 'txt'
            else:
                format_type = 'json'
            
            output_handler.save_results(results, args.output, format_type)
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        raise  # Re-raise to trigger cleanup
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        # Step 6: Comprehensive cleanup
        try:
            stats.end_scan()
            stats.print_summary()
        except Exception:
            pass
        
        if not args.no_cleanup:
            # Clean up all temporary data
            cleanup_all_temp_data()
            
            # Clean up any remaining temp files
            cleanup_temp_files(temp_files)
            
            # Clean up refined file specifically
            if refined_file and os.path.exists(refined_file):
                try:
                    os.unlink(refined_file)
                except Exception:
                    pass

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Cancelled')
        emergency_cleanup()
        sys.exit(0)
    except Exception as e:
        print(f'\n[!] Fatal error: {e}')
        emergency_cleanup()
        sys.exit(1)
