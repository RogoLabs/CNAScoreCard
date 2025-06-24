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
    
    # Clone CVE data if not exists
    if not os.path.exists("cve_data"):
        print("Cloning CVE data repository...")
        subprocess.run(["git", "clone", "https://github.com/CVEProject/cvelistV5.git", "cve_data"], check=True)
    else:
        print("Updating CVE data repository...")
        subprocess.run(["git", "pull"], cwd="cve_data", check=True)
    
    # Generate static data using the main script
    print("Generating static data...")
    subprocess.run([sys.executable, "cnascorecard/generate_static_data.py"], check=True)
    
    print("Build completed successfully!")

if __name__ == "__main__":
    main()