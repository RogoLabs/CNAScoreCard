#!/usr/bin/env python3
"""
Main build script for CNA Score Card
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    """Main build process"""
    print("Building CNA Score Card...")
    
    # Ensure we're in the project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    # Fetch CVE data
    print("Fetching CVE data...")
    subprocess.run([sys.executable, "scripts/fetch_cve_data.py"], check=True)
    
    # Generate main dashboard
    print("Generating main dashboard...")
    subprocess.run([sys.executable, "scripts/generate_dashboard.py"], check=True)
    
    # Generate individual CNA pages
    print("Generating individual CNA pages...")
    subprocess.run([sys.executable, "scripts/generate_cna_pages.py"], check=True)
    
    print("Build completed successfully!")

if __name__ == "__main__":
    main()