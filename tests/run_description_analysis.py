#!/usr/bin/env python3
"""
Simple runner for the description quality analysis test.
"""

import sys
import subprocess
from pathlib import Path

def install_dependencies():
    """Install test dependencies if needed."""
    try:
        import matplotlib, seaborn, sklearn, textblob, pandas, numpy
        print("✅ All dependencies are already installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("Installing test dependencies...")
        
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", 
                str(Path(__file__).parent / "test-requirements.txt")
            ])
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            print("Please manually install: pip install -r test-requirements.txt")
            return False

def main():
    """Run the description quality analysis."""
    print("🔍 CVE Description Quality Analysis Runner")
    print("=" * 50)
    
    if not install_dependencies():
        sys.exit(1)
    
    # Import and run the test
    try:
        from test_description_quality import main as run_analysis
        run_analysis()
    except ImportError:
        print("❌ Could not import test_description_quality module")
        sys.exit(1)

if __name__ == "__main__":
    main()