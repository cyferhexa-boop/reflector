import logging
import sys
from datetime import datetime
from pathlib import Path
from config import LOG_FORMAT, DATE_FORMAT, COLORS

class ReflectorLogger:
    def __init__(self, log_file=None, verbose=False):
        self.verbose = verbose
        self.setup_logger(log_file)
    
    def setup_logger(self, log_file):
        """Setup logging configuration"""
        level = logging.DEBUG if self.verbose else logging.INFO
        
        # Create formatter
        formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        
        # Setup root logger
        logging.basicConfig(level=level, handlers=[console_handler])
        self.logger = logging.getLogger('reflector')
        
        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(file_handler)
    
    def info(self, message, color=None):
        """Log info message with optional color"""
        if color and color in COLORS:
            print(f"{COLORS[color]}{message}{COLORS['RESET']}")
        else:
            print(f"{COLORS['INFO']}[*]{COLORS['RESET']} {message}")
        
        if self.verbose:
            self.logger.info(message)
    
    def success(self, message):
        """Log success message"""
        print(f"{COLORS['SUCCESS']}[+]{COLORS['RESET']} {message}")
        if self.verbose:
            self.logger.info(f"SUCCESS: {message}")
    
    def warning(self, message):
        """Log warning message"""
        print(f"{COLORS['WARNING']}[!]{COLORS['RESET']} {message}")
        if self.verbose:
            self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        print(f"{COLORS['ERROR']}[!]{COLORS['RESET']} {message}")
        self.logger.error(message)
    
    def vulnerability(self, vuln_type, url, param):
        """Log vulnerability finding with enhanced color support"""
        if vuln_type == "XSS+SQL":
            # Yellow XSS + Red SQL
            vuln_display = f"{COLORS['WARNING']}XSS{COLORS['RESET']}+{COLORS['ERROR']}SQL{COLORS['RESET']}"
        else:
            color_map = {
                'SQL': COLORS['ERROR'],      # Red
                'XSS': COLORS['WARNING'],    # Yellow
                'REFLECTION': COLORS['INFO'] # Blue
            }
            color = color_map.get(vuln_type, COLORS['SUCCESS'])
            vuln_display = f"{color}{vuln_type}{COLORS['RESET']}"
        
        print(f"{COLORS['SUCCESS']}[+]{COLORS['RESET']} {vuln_display}: {url} param={param}")
        if self.verbose:
            self.logger.info(f"VULNERABILITY: {vuln_type} - {url} - {param}")
    
    def progress(self, current, total, message="Progress"):
        """Log progress"""
        if total > 0:
            percentage = (current / total) * 100
            print(f"\r{COLORS['INFO']}[*]{COLORS['RESET']} {message}: {current}/{total} ({percentage:.1f}%)", end='', flush=True)

# Global logger instance
logger = None

def get_logger():
    global logger
    if logger is None:
        logger = ReflectorLogger()
    return logger
