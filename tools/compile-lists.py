#!/usr/bin/env python3
import yaml
import os
import hashlib
import re
import sys
import argparse

# Configuration
SOURCE_DIR = "data/source"
COMPILED_DIR = "data/compiled"

# Domain validation regex
DOMAIN_PATTERN = re.compile(
    r'^(?!-)[a-z0-9-]+(?<!-)(\.(?!-)[a-z0-9-]+(?<!-))+$',
    re.IGNORECASE
)

def validate_domain(domain):
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_PATTERN.match(domain))

def get_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def compile_lists(include_proposed=False):
    direct_domains = set()
    vpn_domains = set()
    
    if not os.path.exists(SOURCE_DIR):
        print(f"Error: Source directory '{SOURCE_DIR}' not found.")
        sys.exit(1)

    if not os.path.exists(COMPILED_DIR):
        os.makedirs(COMPILED_DIR)

    print(f"Compiling sources from {SOURCE_DIR} (Include Proposed: {include_proposed})...")

    for filename in os.listdir(SOURCE_DIR):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            file_path = os.path.join(SOURCE_DIR, filename)
            try:
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
                    if not data: continue
                    
                    review = data.get('review', {})
                    status = review.get('status', 'proposed')
                    
                    if status != 'approved' and not include_proposed:
                        continue

                    action = data.get('action')
                    domains = data.get('domains', [])
                    
                    if not isinstance(domains, list): continue

                    for d in domains:
                        d = d.strip().lower()
                        if validate_domain(d):
                            if action == 'direct-wan':
                                direct_domains.add(d)
                            elif action == 'vpn':
                                vpn_domains.add(d)
            except Exception as e:
                print(f"Error processing {filename}: {e}")

    def write_list(name, domain_set):
        file_path = os.path.join(COMPILED_DIR, name)
        with open(file_path, 'w', newline='\n') as f:
            for d in sorted(list(domain_set)):
                f.write(f"{d}\n")
        print(f"Generated {name} with {len(domain_set)} domains.")
        return name

    files_to_hash = []
    files_to_hash.append(write_list("direct-domains.txt", direct_domains))
    files_to_hash.append(write_list("vpn-domains.txt", vpn_domains))

    checksum_path = os.path.join(COMPILED_DIR, "sha256sums.txt")
    with open(checksum_path, 'w', newline='\n') as f:
        for f_name in files_to_hash:
            path = os.path.join(COMPILED_DIR, f_name)
            if os.path.exists(path):
                file_hash = get_sha256(path)
                f.write(f"{file_hash}  {f_name}\n")
    
    print("Compilation successful.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PBRCloud List Compiler")
    parser.add_argument("--include-proposed", action="store_true", help="Include records with 'proposed' status")
    args = parser.parse_args()
    
    compile_lists(include_proposed=args.include_proposed)
