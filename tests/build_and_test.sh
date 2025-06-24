#!/bin/bash

# Build and Test Script for CNA ScoreCard
# This script builds the project locally and starts a test server

set -e  # Exit on any error

echo "🚀 Starting CNA ScoreCard build and test process..."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if Git is available
if ! command -v git &> /dev/null; then
    echo "❌ Git is required but not installed."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Clone CVE data if not already present
if [ ! -d "cve_data" ]; then
    echo "📊 Cloning CVE data repository..."
    git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cve_data
else
    echo "📊 Updating CVE data repository..."
    cd cve_data
    git pull origin main
    cd ..
fi

# Generate static data
echo "⚙️  Generating static data..."
python cnascorecard/generate_static_data.py

# Check if data was generated successfully
if [ ! -f "web/data/cnas.json" ]; then
    echo "❌ Failed to generate CNA data"
    exit 1
fi

echo "✅ Data generation complete!"

# Count the generated data
CNA_COUNT=$(python3 -c "import json; data=json.load(open('web/data/cnas.json')); print(len(data))")
echo "📈 Generated data for $CNA_COUNT CNAs"

# Check if we have CVE data files
if [ -f "web/data/top100_cves.json" ]; then
    TOP_CVE_COUNT=$(python3 -c "import json; data=json.load(open('web/data/top100_cves.json')); print(len(data))")
    echo "📈 Generated top $TOP_CVE_COUNT CVEs"
fi

if [ -f "web/data/bottom100_cves.json" ]; then
    BOTTOM_CVE_COUNT=$(python3 -c "import json; data=json.load(open('web/data/bottom100_cves.json')); print(len(data))")
    echo "📈 Generated bottom $BOTTOM_CVE_COUNT CVEs"
fi

# Start local server
echo ""
echo "🌐 Starting local development server..."
echo "📍 Your site will be available at: http://localhost:8000"
echo "🔧 Press Ctrl+C to stop the server"
echo ""

# Change to web directory and start server
cd web
python3 -m http.server 8000

# Cleanup on exit
trap 'echo "🛑 Stopping server..."; exit 0' INT

