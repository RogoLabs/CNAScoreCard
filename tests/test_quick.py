#!/usr/bin/env python3
"""
Quick test runner for CNA ScoreCard
Tests data generation and validates JSON structure
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and return success status"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return False

def main():
    """Run test sequence"""
    print("🧪 Running CNA ScoreCard tests...\n")
    
    # Check if we're in the right directory
    if not Path("generate_static_data.py").exists():
        print("❌ Please run this script from the project root directory")
        return False
    
    # Test 1: Generate static data
    if not run_command("python generate_static_data.py", "Generating static data"):
        return False
    
    # Test 2: Validate data structure
    if not run_command("python test_data_structure.py", "Validating data structure"):
        return False
    
    # Test 3: Check that web files exist
    web_files = [
        "web/index.html",
        "web/script.js",
        "web/styles.css",
        "web/data/cnas.json"
    ]
    
    print("\n🔍 Checking web files...")
    for file_path in web_files:
        if Path(file_path).exists():
            print(f"✅ {file_path} exists")
        else:
            print(f"❌ {file_path} missing")
            return False
    
    print("\n🎉 All tests passed!")
    print("\nTo test locally:")
    print("1. Run: ./build_and_test.sh")
    print("2. Open: http://localhost:8000")
    print("\nTo deploy:")
    print("1. Commit your changes")
    print("2. Push to GitHub")
    print("3. GitHub Actions will deploy automatically")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)