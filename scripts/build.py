#!/usr/bin/env python3
"""
CNA ScoreCard Build Script
Generates static data files for the CNA ScoreCard web application.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {cmd}")
            print(f"Error: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"Exception running command {cmd}: {e}")
        return False

def main():
    print("Building CNA Score Card...")
    
    # Get the script directory
    script_dir = Path(__file__).parent.absolute()
    project_root = script_dir.parent
    
    # Change to project root
    os.chdir(project_root)
    
    # Update CVE data repository
    print("Updating CVE data repository...")
    if not run_command("cd cve_data && git pull"):
        print("Failed to update CVE data")
        return 1
    
    # Generate static data
    print("Generating static data...")
    if not run_command("python scripts/generate_static_data.py"):
        print("Failed to generate static data")
        return 1
    
    # Copy generated files to ensure they're available
    web_dir = project_root / "web"
    if web_dir.exists():
        print("Web directory structure ready")
    
    print("Build completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())