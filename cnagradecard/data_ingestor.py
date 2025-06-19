import os
import requests
import zipfile
import io
import json
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
    Downloads and filters CVE records from the last 6 months.
    """
    url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
    print("Downloading CVE data...")
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading CVE data: {e}")
        return []

    print("Filtering records...")
    zip_file = zipfile.ZipFile(io.BytesIO(response.content))
    
    six_months_ago = datetime.now() - timedelta(days=180)
    
    recent_cves = []
    
    for file_info in zip_file.infolist():
        if file_info.filename.endswith('.json') and 'cves/' in file_info.filename:
            # Extract the content of the json file
            with zip_file.open(file_info) as file:
                try:
                    cve_data = json.load(file)
                    date_published_str = cve_data.get('cveMetadata', {}).get('datePublished')
                    if date_published_str:
                        date_published = datetime.fromisoformat(date_published_str.replace('Z', '+00:00'))
                        if date_published.replace(tzinfo=None) >= six_months_ago:
                            recent_cves.append(cve_data)
                except json.JSONDecodeError:
                    # Not a valid JSON file, skip
                    continue
                except Exception as e:
                    print(f"Error processing file {file_info.filename}: {e}")


    print(f"Found {len(recent_cves)} recent CVEs.")
    return recent_cves

if __name__ == '__main__':
    cna_list = get_cna_list()
    if cna_list:
        print(f"Successfully downloaded {len(cna_list)} CNA records.")
    
    cve_records = get_cve_records()
    # You can add further processing here if needed
