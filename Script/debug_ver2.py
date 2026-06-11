
import msgspec
import logging
from pathlib import Path
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
from utility import get_all_vt_ai_files, get_qk_files, load_pkg2hash, load_apk_files

# LOG_FILE = '/shared/frankzha/data/log_file/malformed_json_files.log'
BAD_VT_FILE = '/shared/frankzha/data/log_file/malformed_vt_files.txt'
BAD_QK_FILE = '/shared/frankzha/data/log_file/malformed_qk_files.txt'
"""
# Logging configuration
# def configure_logging():
#     out_dir = Path(LOG_FILE)
#     out_dir.mkdir(parents=True, exist_ok=True)
#     logging.basicConfig(
#         filename=out_dir / 'scan_invalid_json.log',
#         level=logging.INFO,
#         format='%(asctime)s %(levelname)s %(message)s'
#     )
#     logging.info('Starting JSON validity scan')


def is_json_valid(path: Path) -> bool:
    try:
        raw = path.read_bytes().decode("utf-8-sig", errors="replace")
        msgspec.json.decode(raw)
        return True
    except (msgspec.DecodeError, UnicodeDecodeError):
        return False


def scan_pair(pair):
    vt_path, qk_path = pair
    return (
        vt_path, is_json_valid(vt_path),
        qk_path, is_json_valid(qk_path)
    )


def main():
    # configure_logging()
    
    vt_ai_stem2path = {p.stem: p for p in get_all_vt_ai_files()}
    qk_stem2path = {p.stem: p for p in get_qk_files()}
    vt_qk_files = sorted(
        (vt_ai_stem2path[s], qk_stem2path[s])
        for s in vt_ai_stem2path.keys() & qk_stem2path.keys()
    )
    # logging.info(f'Found {len(vt_qk_files)} common file pairs')
    print(f'There are {len(vt_ai_stem2path)} VirusTotal (v3) responses.')
    print(f'There are {len(qk_stem2path)} Quark-engine responses.')
    print(f'There are {len(vt_qk_files)} common files.')

    with Pool(processes=cpu_count() // 4) as pool, \
         open(BAD_VT_FILE, 'w', encoding='utf-8') as f_vt, \
         open(BAD_QK_FILE, 'w', encoding='utf-8') as f_qk:
        try:
            for vt_path, vt_ok, qk_path, qk_ok in tqdm(
                pool.imap_unordered(scan_pair, vt_qk_files),
                total=len(vt_qk_files),
                desc='Scanning JSON'
            ):
                if not vt_ok:
                    f_vt.write(str(vt_path.absolute()) + '\n')
                    # logging.warning(f'Malformed VT JSON: {vt_path}')
                if not qk_ok:
                    f_qk.write(str(qk_path.absolute()) + '\n')
                    # logging.warning(f'Malformed QK JSON: {qk_path}')
                    
        except KeyboardInterrupt:
            # logging.error('Interrupted by user')
            pool.terminate()
            pool.join()
            raise

    # logging.info('Scan complete')
    print(f"Scan finished.")


if __name__ == '__main__':
    main()
"""  

"""
# [2] The script below saves the single malformed VT response
import os
import json
import requests

API_KEY = "c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0"
HASH_TO_CHECK = "8d04aebe731b33031912b88ee3edadcb"
DESTINATION_PATH = "/shared/frankzha/data/log_file/rescanned_vt_files"  # Saves to a 'vt_reports' folder where the script is run


print(f"Requesting report for hash: {HASH_TO_CHECK}...")

# Define the API endpoint and authentication headers
url = f"https://www.virustotal.com/api/v3/files/{HASH_TO_CHECK}"
headers = {"x-apikey": API_KEY}

try:
    # Make the API request
    response = requests.get(url, headers=headers)

    # Handle a successful response (HTTP 200)
    if response.status_code == 200:
        print("Success! Saving report.")
        
        # Create the destination directory if it doesn't exist
        os.makedirs(DESTINATION_PATH, exist_ok=True)
        
        # Define the full path for the output file
        output_file_path = os.path.join(DESTINATION_PATH, f"{HASH_TO_CHECK}.json")
        
        # Save the JSON data to the file with nice formatting
        with open(output_file_path, 'w') as f:
            json.dump(response.json(), f, indent=2)
        
        print(f"Report saved to: {output_file_path}")

    # Handle "Not Found" error (HTTP 404)
    elif response.status_code == 404:
        print("Error: Hash was not found in VirusTotal's database.")
        
    # Handle all other errors (e.g., bad API key, quota exceeded)
    else:
        print(f"An error occurred. Status Code: {response.status_code}")
        print(f"Details: {response.text}")

except requests.exceptions.RequestException as e:
    # Handle network-level errors (e.g., no internet connection)
    print(f"A network error occurred: {e}")
    


import msgspec
from pathlib import Path

def is_json_valid(path: Path) -> bool:
    try:
        raw = path.read_bytes().decode("utf-8-sig", errors="replace")
        msgspec.json.decode(raw)
        return True
    except (msgspec.DecodeError, UnicodeDecodeError):
        return False


print(is_json_valid(Path('/shared/frankzha/data/log_file/rescanned_vt_files/8d04aebe731b33031912b88ee3edadcb.json')))


import os
import json
import requests
import re
import msgspec
from pathlib import Path

# --- Configuration ---
API_KEY = "c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0"
HASH_TO_CHECK = "8d04aebe731b33031912b88ee3edadcb"
DESTINATION_PATH = "/shared/frankzha/data/log_file/rescanned_vt_files"

# --- NEW, MORE ROBUST JSON FIXING FUNCTION ---
def robust_json_string_fixer(text: str) -> str:
    '''
    Finds all string literals in a text and re-encodes them using json.dumps.
    This correctly handles ALL special characters (newlines, tabs, other control
    characters, backslashes, quotes) according to the JSON standard.
    '''
    # The regex is the same, it finds the content of a string literal
    # The replacer function is now a simple lambda that calls json.dumps
    return re.sub(
        r'"((?:\\.|[^"\\])*)"',
        lambda match: json.dumps(match.group(1)),
        text,
        flags=re.DOTALL
    )

# --- Main Logic ---
print(f"Requesting report for hash: {HASH_TO_CHECK}...")

url = f"https://www.virustotal.com/api/v3/files/{HASH_TO_CHECK}"
headers = {"x-apikey": API_KEY}

try:
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("Success! Report received. Applying ROBUST fix before saving.")
        
        # 1. Get the raw text from the response.
        raw_text = response.text

        # 2. Apply our new, more powerful fixing function.
        fixed_text = robust_json_string_fixer(raw_text)

        # 3. Save the fixed text directly to a file.
        #    We can dump the text itself since we've constructed a valid JSON string.
        os.makedirs(DESTINATION_PATH, exist_ok=True)
        output_file_path = os.path.join(DESTINATION_PATH, f"{HASH_TO_CHECK}.json")
        
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_text)
        
        print(f"Strictly compliant report saved to: {output_file_path}")

    elif response.status_code == 404:
        print(f"Error: Hash '{HASH_TO_CHECK}' was not found in VirusTotal's database.")
    else:
        print(f"An error occurred. Status Code: {response.status_code}")
        print(f"Details: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"A network error occurred: {e}")


# --- Validation Step ---
def is_json_valid(path: Path) -> bool:
    if not path.exists():
        print(f"Validation Error: File '{path}' does not exist.")
        return False
    try:
        raw = path.read_bytes().decode("utf-8-sig")
        msgspec.json.decode(raw)
        return True
    except (msgspec.DecodeError, UnicodeDecodeError) as e:
        print(f"Validation failed with error: {e}") # Added error logging
        return False

expected_file_path = Path(DESTINATION_PATH) / f"{HASH_TO_CHECK}.json"
print(f"\nRunning validation on '{expected_file_path}'...")
is_valid = is_json_valid(expected_file_path)
print(f"Is the saved file valid? -> {is_valid}")

if is_valid:
    print("\n✅ The new fixing method worked and the file is now valid according to the strict parser.")
"""


import os
import sys
import subprocess
from pathlib import Path
import multiprocessing

from utility import load_hash2folder

# --- Global configuration ---
APK_DIR_PATH = '/mnt/data/Android-Data/APKs'
RULE_DIR = '/home/umflint.edu/frankzha/.quark-engine/quark-rules/rules'
QUARK_RESCAN_PATH = "/shared/frankzha/data/log_file/rescanned_qk_files"  # All rescanned JSON files will go here.

# MAX_WORKERS = multiprocessing.cpu_count() // 2
MAX_WORKERS = 20
MAX_TIMEOUT = 50 * 60

h2f = load_hash2folder()

def process_apk(apk_tuple):
    """Process a single APK: run Quark rescan and save JSON report."""
    apk_file, pkg_name = apk_tuple
    # print(f"[DEBUG] Starting process_apk: apk_file={apk_file}, pkg={pkg_name}")
    hash_value = pkg2hash[pkg_name]
    # print(f"[DEBUG] Retrieved hash_value={hash_value} for pkg_name={pkg_name}")
    folder_name = h2f[hash_value]
    
    apk_path = os.path.join(APK_DIR_PATH, folder_name, apk_file + '.apk')
    # print(f'{hash_value=}, {folder_name=}, {apk_path=}')
    inline_code = f"""
import os, json
from quark.report import Report
apk_path = {repr(apk_path)}
RULE_DIR = {repr(RULE_DIR)}
OUTPUT_DIR = {repr(QUARK_RESCAN_PATH)}
report = Report()
report.analysis(apk_path, RULE_DIR)
json_report = report.get_report("json")
# md5 = json_report['md5']
folder_name = {repr(folder_name)}
md5 = {repr(hash_value)}
report_path = os.path.join(OUTPUT_DIR, folder_name, md5 + '.json')
os.makedirs(os.path.dirname(report_path), exist_ok=True)
with open(report_path, 'w') as file:
    json.dump(json_report, file, indent=4)
"""
    try:
        subprocess.run(
            [sys.executable, "-c", inline_code],
            timeout=MAX_TIMEOUT,
            check=True
        )
        # print(f"[DEBUG] subprocess completed for {apk_path}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] subprocess failed for {apk_path}: {e}")
        return None
    except subprocess.TimeoutExpired as e:
        print(f"[ERROR] subprocess timeout for {apk_path}: {e}")
        return None

    return hash_value


def main():
    """Main entry: spin up worker pool and process APKs."""
    scanned_n = 0
    os.makedirs(QUARK_RESCAN_PATH, exist_ok=True)
    print(f"[DEBUG] Output directory ensured: {QUARK_RESCAN_PATH}")
    print(f"[DEBUG] Launching pool with {MAX_WORKERS} workers")
    
    pool = multiprocessing.Pool(processes=MAX_WORKERS)
    for result_hash in tqdm(
        pool.imap_unordered(process_apk, apk_files),
        total=len(apk_files),
        desc='Rescanning malformed Quark-engine reports'
    ):
        # print(f"[DEBUG] Received result_hash={result_hash}")
        if result_hash:
            scanned_n += 1
        #     # print(f"[{scanned_n}/{len(apk_files)}] [S] {result_hash} scanned")
        # else:
            # print(f"[DEBUG] Skipped or failed a job, total scanned still {scanned_n}")
        
    pool.close()
    pool.join()

    print(f"\n[Summary] Successfully scanned {scanned_n} files out of {len(apk_files)}")


if __name__ == "__main__":
    # We assume we have the list of hashes we want to scan
    hashes_to_scan = set()
    with open(BAD_QK_FILE, 'r') as f:
        for line in f:
            path_str = line.strip()
            if not path_str:
                continue
            hashes_to_scan.add(Path(path_str).stem)
            
    assert len(hashes_to_scan) == 1581
    
    print(f'[DEBUG] Found {len(hashes_to_scan)} total target hashes in {BAD_QK_FILE}')
    
    h2f = load_hash2folder()
    pkg2hash = load_pkg2hash()
    print(f"[DEBUG] Loaded pkg2hash mapping with {len(pkg2hash)} entries")
    raw_apks = load_apk_files()
    print(f"[DEBUG] Loaded raw_apks list with {len(raw_apks)} items")

    # Pre-filter and attach subfolder/pkg tuples
    to_scan_apks = []
    for apk in raw_apks:
        pkg_name = apk.removesuffix('.apk')
        if pkg2hash.get(pkg_name) in hashes_to_scan:
            to_scan_apks.append((apk, pkg_name))
    
    apk_files = to_scan_apks
    print(f"[DEBUG] Will scan {len(apk_files)} APKs …")

    main()
    
# FileNotFoundError: [Errno 2] No such file or directory: '/mnt/data/Android-Data/APKs/com.agora_vai_corp.memegic'