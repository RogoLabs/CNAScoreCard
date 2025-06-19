#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define the image and container names
IMAGE_NAME="cnagradecard"
CONTAINER_NAME="cnacard-test"
CVE_DATA_DIR="./cve_data"
REPO_URL="https://github.com/CVEProject/cvelistV5.git"

# --- Data Preparation on Host ---
echo "Preparing CVE data on the host..."
if [ -d "$CVE_DATA_DIR" ]; then
    echo "Updating existing CVE repository..."
    git -C "$CVE_DATA_DIR" pull
else
    echo "Cloning CVE repository for the first time (this may take several minutes)..."
    git clone --depth 1 "$REPO_URL" "$CVE_DATA_DIR"
fi
echo "CVE data is ready."


# Build the Docker container
echo "Building Docker container..."
docker build -t $IMAGE_NAME .

# Stop and remove any previous container with the same name
docker stop $CONTAINER_NAME >/dev/null 2>&1 || true
docker rm $CONTAINER_NAME >/dev/null 2>&1 || true

# Run the Docker container in detached mode, mapping the local cve_data directory
echo "Launching Docker container..."
docker run -d -p 80:80 --name $CONTAINER_NAME -v "$(pwd)/cve_data:/app/cve_data" $IMAGE_NAME

# Wait for the application to start up and process data
echo "Waiting for application to be ready..."
ATTEMPTS=0
# Try for 2 minutes (24 * 5 seconds)
MAX_ATTEMPTS=24

until curl -s -f -o /dev/null http://localhost:80/api/cnas; do
    if [ ${ATTEMPTS} -eq ${MAX_ATTEMPTS} ]; then
        echo "Application did not become ready in time. Aborting."
        echo "Dumping container logs for debugging:"
        docker logs $CONTAINER_NAME
        exit 1
    fi
    ATTEMPTS=$((ATTEMPTS + 1))
    printf "."
    sleep 5
done

echo "\nApplication is ready!"


# Test the API endpoints and save the pretty-printed output
echo "Testing API endpoints..."

curl -s http://localhost:80/api/cnas | python -m json.tool > output/cnas.json
echo "Saved all CNA reports to output/cnas.json"

curl -s http://localhost:80/api/cna/microsoft | python -m json.tool > output/microsoft_cna.json
echo "Saved Microsoft CNA report to output/microsoft_cna.json"

curl -s http://localhost:80/api/cves/top100 | python -m json.tool > output/top100_cves.json
echo "Saved top 100 CVEs to output/top100_cves.json"

curl -s http://localhost:80/api/cves/bottom100 | python -m json.tool > output/bottom100_cves.json
echo "Saved bottom 100 CVEs to output/bottom100_cves.json"

# Stop and remove the container
echo "Stopping and removing container..."
docker stop $CONTAINER_NAME
docker rm $CONTAINER_NAME

echo "Build and test script finished successfully."
