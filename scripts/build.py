#!/usr/bin/env python3
"""
Main build script for CNA ScoreCard.
Generates all static data and pages.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors."""
    print(f"{description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed successfully")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed:")
        print(f"Error code: {e.returncode}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return False

def main():
    """Main build process."""
    print("Starting CNA ScoreCard build process...")
    
    # Ensure we're in the right directory
    script_dir = Path(__file__).parent.parent
    os.chdir(script_dir)
    
    # Step 1: Generate static data (this creates JSON files and CNA pages)
    if not run_command("python cnascorecard/generate_static_data.py", "Generating static data"):
        sys.exit(1)
    
    print("\n🎉 Build completed successfully!")
    print("All static files have been generated in the web/ directory.")

if __name__ == "__main__":
    main()