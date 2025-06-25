#!/usr/bin/env python3
"""
Extract all valid CWE IDs from cwec_v4.17.xml and save them to cwe_ids.json
"""
import xml.etree.ElementTree as ET
import json
import os

# Set paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XML_PATH = os.path.join(BASE_DIR, "cnascorecard", "cwec_v4.17.xml")
OUT_PATH = os.path.join(BASE_DIR, "cnascorecard", "cwe_ids.json")


def extract_cwe_ids(xml_path):
    cwe_ids = set()
    for event, elem in ET.iterparse(xml_path, events=("start",)):
        if elem.tag.endswith('Weakness') and 'ID' in elem.attrib:
            cwe_ids.add(str(elem.attrib['ID']))
    return sorted(cwe_ids, key=lambda x: int(x) if x.isdigit() else x)


def main():
    if not os.path.exists(XML_PATH):
        print(f"Error: {XML_PATH} not found.")
        return
    cwe_ids = extract_cwe_ids(XML_PATH)
    with open(OUT_PATH, "w") as f:
        json.dump(cwe_ids, f, indent=2)
    print(f"Extracted {len(cwe_ids)} CWE IDs to {OUT_PATH}")

if __name__ == "__main__":
    main()
