"""
sync_cna_list.py: Download and sync official CNAs list from CVE Project GitHub repository.
Ensures web/data/cna_list.json stays current with daily updates.
"""

import json
import logging
import os
import requests
from typing import Dict, List, Any
from pathlib import Path


def download_official_cnas_list() -> List[Dict[str, Any]]:
    """Download the official CNAs list from CVE Project GitHub repository."""
    url = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
    
    try:
        logging.info(f"Downloading official CNAs list from: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        logging.info(f"Successfully downloaded {len(data)} CNAs from official list")
        return data
        
    except requests.RequestException as e:
        logging.error(f"Failed to download CNAs list: {e}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse CNAs list JSON: {e}")
        raise


def create_enhanced_cna_list(official_cnas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Create enhanced CNA list with essential metadata for frontend use."""
    enhanced_cnas = []
    
    for cna in official_cnas:
        # Robust shortName extraction
        short_name = cna.get('shortName') or cna.get('ShortName') or cna.get('cnaShortName')
        if not short_name:
            # Fallback: try to construct from organizationName or cnaID
            if 'organizationName' in cna:
                short_name = cna['organizationName'].replace(' ', '_').lower()
            elif 'cnaID' in cna:
                short_name = cna['cnaID']
            else:
                logging.warning(f"Skipping CNA with no shortName or fallback: {cna}")
                continue
        root_cna_info = {}
        if 'CNA' in cna and 'root' in cna['CNA']:
            # Only use if not a placeholder
            if cna['CNA']['root'].get('shortName', '').lower() != 'n/a':
                root_cna_info = cna['CNA']['root']
            elif 'rootCnaInfo' in cna:
                root_cna_info = cna['rootCnaInfo']
        elif 'rootCnaInfo' in cna:
            root_cna_info = cna['rootCnaInfo']
        if not root_cna_info:
            root_cna_info = {}
        # Robustly extract cnaID and type from any possible location
        cna_id = cna.get('cnaID', '')
        cna_types = cna.get('type', [])
        if 'CNA' in cna:
            cna_id = cna['CNA'].get('cnaID', '') or cna_id
            cna_types = cna['CNA'].get('type', cna_types)
        # Ensure cna_types is always a list
        if isinstance(cna_types, str):
            cna_types = [cna_types]
        elif not isinstance(cna_types, list):
            cna_types = []
        enhanced_cna = {
            'shortName': short_name,
            'organizationName': cna.get('organizationName', short_name),
            'scope': cna.get('scope', ''),
            'cnaID': cna_id,
            'type': cna_types,
            'advisories': [],
            'email': [],
            'country': cna.get('country', ''),
            'disclosurePolicy': cna.get('disclosurePolicy', []),
            'rootCnaInfo': root_cna_info
        }
        if 'CNA' in cna and 'root' in cna['CNA']:
            # Only use if not a placeholder
            if cna['CNA']['root'].get('shortName', '').lower() != 'n/a':
                root_cna_info = cna['CNA']['root']
            elif 'rootCnaInfo' in cna:
                root_cna_info = cna['rootCnaInfo']
        elif 'rootCnaInfo' in cna:
            root_cna_info = cna['rootCnaInfo']
        # If still empty, set to empty dict
        if not root_cna_info:
            root_cna_info = {}
        # Robustly extract cnaID and type
        cna_id = ''
        cna_types = []
        if 'CNA' in cna:
            cna_id = cna['CNA'].get('cnaID', '') or cna.get('cnaID', '')
            cna_types = cna['CNA'].get('type', [])
        else:
            cna_id = cna.get('cnaID', '')
            cna_types = cna.get('type', [])
        # Ensure cna_types is always a list
        if isinstance(cna_types, str):
            cna_types = [cna_types]
        elif not isinstance(cna_types, list):
            cna_types = []
        enhanced_cna = {
            'shortName': cna['shortName'],
            'organizationName': cna.get('organizationName', cna['shortName']),
            'scope': cna.get('scope', ''),
            'cnaID': cna_id,
            'type': cna_types,
            'advisories': [],
            'email': [],
            'country': cna.get('country', ''),
            'disclosurePolicy': cna.get('disclosurePolicy', []),
            'rootCnaInfo': root_cna_info
        }
        
        # Extract CNA type
        if 'CNA' in cna and 'type' in cna['CNA']:
            enhanced_cna['type'] = cna['CNA']['type']
        
        # Extract advisories
        if 'securityAdvisories' in cna and 'advisories' in cna['securityAdvisories']:
            enhanced_cna['advisories'] = cna['securityAdvisories']['advisories']
        
        # Extract email contacts
        if 'contact' in cna:
            for contact in cna['contact']:
                if 'email' in contact:
                    enhanced_cna['email'].extend(contact['email'])
        
        enhanced_cnas.append(enhanced_cna)
    
    # Sort by organization name for consistent ordering
    enhanced_cnas.sort(key=lambda x: x['organizationName'].lower())
    
    logging.info(f"Created enhanced CNA list with {len(enhanced_cnas)} entries")
    return enhanced_cnas


def save_cna_lists(official_cnas: List[Dict[str, Any]], enhanced_cnas: List[Dict[str, Any]]) -> None:
    """Save CNA list files needed for pipeline operation.
    
    Note: While these files are not used by web pages, cna_list.json is required
    internally by the pipeline for CNA metadata. We only skip official_cnas_list.json
    which is truly unused.
    """
    
    # Determine the web/data directory path
    current_dir = Path(__file__).parent
    web_data_dir = current_dir.parent / 'web' / 'data'
    web_data_dir.mkdir(parents=True, exist_ok=True)
    
    # Skip raw official CNAs list (truly unused)
    logging.info("Skipping official_cnas_list.json generation - not used by web interface or pipeline")
    
    # Save enhanced CNA list for pipeline internal use (required for CNA metadata)
    enhanced_file = web_data_dir / 'cna_list.json'
    with open(enhanced_file, 'w', encoding='utf-8') as f:
        json.dump(enhanced_cnas, f, indent=2, ensure_ascii=False)
    logging.info(f"Saved enhanced CNA list to: {enhanced_file} (required for pipeline operation)")


def sync_cna_list() -> bool:
    """Main function to sync the CNAs list. Returns True if successful."""
    try:
        logging.info("Starting CNAs list sync...")
        
        # Download official CNAs list
        official_cnas = download_official_cnas_list()
        
        # Create enhanced version for frontend
        enhanced_cnas = create_enhanced_cna_list(official_cnas)
        
        # Save both versions
        save_cna_lists(official_cnas, enhanced_cnas)
        
        logging.info("CNAs list sync completed successfully")
        return True
        
    except Exception as e:
        logging.error(f"CNAs list sync failed: {e}")
        return False


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Run the sync
    success = sync_cna_list()
    exit(0 if success else 1)
