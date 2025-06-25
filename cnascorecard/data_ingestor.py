import os
import requests
import json
import subprocess
from datetime import datetime, timedelta

def get_cna_list():
    """
    Downloads the master CNA list.
    """
    url = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading CNA list: {e}")
        return None

def get_cve_records():
    """
    Reads CVE records from the local cve_data directory and filters them for the last 6 months.
    Clones the repository if it doesn't exist.
    """
    # Path to the data directory, which is mapped from the host
    clone_path = os.path.join(os.path.dirname(__file__), '..', 'cve_data')

    if not os.path.exists(clone_path):
        print(f"CVE data directory not found at {clone_path}")
        print("Cloning CVE data repository...")
        try:
            # Clone the CVE data repository
            parent_dir = os.path.dirname(clone_path)
            subprocess.run([
                'git', 'clone', '--depth', '1',
                'https://github.com/CVEProject/cvelistV5.git',
                clone_path
            ], cwd=parent_dir, check=True, capture_output=True, text=True)
            print("Successfully cloned CVE data repository")
        except subprocess.CalledProcessError as e:
            print(f"Error cloning CVE data repository: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return []
        except Exception as e:
            print(f"Unexpected error cloning CVE data repository: {e}")
            return []

    print("Filtering records from local CVE data...")
    six_months_ago = datetime.now() - timedelta(days=180)
    recent_cves = []
    cves_path = os.path.join(clone_path, 'cves')

    file_count = 0
    for root, _, files in os.walk(cves_path):
        for file in files:
            if file.startswith('CVE-') and file.endswith('.json'):
                file_count += 1
    print(f"Found {file_count} CVE JSON files in cve_data/cves")

    processed = 0
    for root, _, files in os.walk(cves_path):
        for file in files:
            if file.startswith('CVE-') and file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    try:
                        cve_data = json.load(f)
                        # Skip REJECTED CVEs
                        state = cve_data.get('cveMetadata', {}).get('state', '').upper()
                        if state == 'REJECTED':
                            continue
                        date_published_str = cve_data.get('cveMetadata', {}).get('datePublished')
                        if date_published_str:
                            date_published = datetime.fromisoformat(date_published_str.replace('Z', '+00:00'))
                            if date_published.replace(tzinfo=None) >= six_months_ago:
                                recent_cves.append(cve_data)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        print(f"Error processing file {file_path}: {e}")
                processed += 1
                if processed % 1000 == 0:
                    print(f"Processed {processed} files...")

    print(f"Found {len(recent_cves)} recent CVEs.")
    return recent_cves

if __name__ == '__main__':
    cna_list = get_cna_list()
    if cna_list:
        print(f"Successfully downloaded {len(cna_list)} CNA records.")
    
    cve_records = get_cve_records()
    # You can add further processing here if needed
