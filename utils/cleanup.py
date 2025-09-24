import os
import shutil
from pathlib import Path
from typing import List

def cleanup_temp_files(temp_files: List[str]):
    """Clean up temporary files"""
    if not temp_files:
        return
    
    cleaned = 0
    for temp_file in temp_files:
        try:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                cleaned += 1
        except Exception as e:
            print(f"[!] Failed to cleanup {temp_file}: {e}")
    
    if cleaned > 0:
        print(f"[*] Cleaned up {cleaned} temporary file(s)")

def cleanup_scanner_folder():
    """Clean up entire scanner folder and all its contents"""
    scanner_path = Path("scanner")
    
    if scanner_path.exists():
        try:
            # Remove all files in scanner directory
            for file_path in scanner_path.iterdir():
                if file_path.is_file():
                    file_path.unlink()
            
            # Remove the directory itself
            scanner_path.rmdir()
            print("[*] Cleaned up scanner folder")
            
        except Exception as e:
            print(f"[!] Failed to cleanup scanner folder: {e}")

def cleanup_all_temp_data():
    """Clean up all temporary data created by the tool"""
    # Clean up scanner folder
    cleanup_scanner_folder()
    
    # Clean up any other temp files in current directory
    current_dir = Path(".")
    temp_patterns = [
        "wayback_*.txt",
        "collected_urls_*.txt", 
        "merged_urls_*.txt",
        "refine-url*.txt",
        "reflector_*.txt"
    ]
    
    cleaned = 0
    for pattern in temp_patterns:
        for temp_file in current_dir.glob(pattern):
            try:
                temp_file.unlink()
                cleaned += 1
            except Exception:
                pass
    
    if cleaned > 0:
        print(f"[*] Cleaned up {cleaned} additional temp files")

def cleanup_single_file(file_path: str) -> bool:
    """Clean up a single temporary file"""
    try:
        if os.path.exists(file_path):
            os.unlink(file_path)
            return True
    except Exception:
        pass
    return False

def emergency_cleanup():
    """Emergency cleanup on script interruption"""
    try:
        cleanup_all_temp_data()
    except Exception:
        pass  # Silent cleanup on emergency
