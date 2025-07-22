"""
output.py: Write all required JSON files to web/data for the frontend.
"""
import os
import json

def write_json(data, filename, out_dir="../web/data"):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote {filename} to {out_dir}")
