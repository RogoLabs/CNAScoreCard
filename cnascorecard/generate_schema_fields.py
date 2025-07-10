import json
import requests
import os

def extract_fields(schema, prefix="", required_fields=None):
    fields = []
    if required_fields is None:
        required_fields = set(schema.get("required", []))
    properties = schema.get("properties", {})
    for key, value in properties.items():
        field_name = f"{prefix}{key}" if prefix else key
        desc = value.get("description", "")
        is_required = key in schema.get("required", [])
        fields.append({
            "name": field_name,
            "description": desc,
            "required": is_required
        })
        # Recurse into nested objects
        if value.get("type") == "object" and "properties" in value:
            fields.extend(extract_fields(value, field_name + "."))
        # Handle arrays of objects
        elif value.get("type") == "array" and "items" in value and value["items"].get("type") == "object":
            fields.extend(extract_fields(value["items"], field_name + "."))
    return fields

def main():
    schema_url = "https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema/docs/CVE_Record_Format_bundled.json"
    out_path = os.path.join(os.path.dirname(__file__), "cve_schema_fields.json")
    print(f"Downloading schema from {schema_url} ...")
    resp = requests.get(schema_url)
    resp.raise_for_status()
    schema = resp.json()
    print("Extracting fields...")
    fields = extract_fields(schema)
    print(f"Extracted {len(fields)} fields.")
    with open(out_path, "w") as f:
        json.dump(fields, f, indent=2)
    print(f"Wrote {out_path}")

if __name__ == "__main__":
    main()
