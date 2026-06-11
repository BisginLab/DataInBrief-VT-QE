import os
import sys
import json
import time
import pickle
import subprocess
from pathlib import Path
import multiprocessing


# --- Global configuration ---
APK_DIR_PATH = '/mnt/data/Android-Data/APKs'
RULE_DIR = '/home/umflint.edu/frankzha/.quark-engine/quark-rules/rules'
JSON_FILES_PATH = '/shared/frankzha/data/_past_json_reports/json_reports'
QUARK_FST_SCAN_PATH = "/shared/frankzha/data/quark_engine_results/qk_fst_scan"

CHECKPOINT_FILE_PATH = '/shared/frankzha/data/quark_engine_results/qk_rescan/quark_checkpoint.txt'
ERROR_FILE_PATH = '/shared/frankzha/data/quark_engine_results/qk_rescan/quark_error.txt'
TIMEOUT_FILE_PATH = '/shared/frankzha/data/quark_engine_results/qk_rescan/quark_timeout.txt'
QUARK_RESCAN_PATH = "/shared/frankzha/data/quark_engine_results/qk_rescan"

# [note] multiprocessing.cpu_count() outputs 32, so we halve it so be safe.
# If all (or most) cores are used, the system really slows down and you can feel it.
MAX_WORKERS = multiprocessing.cpu_count() // 2

# [note] To prevent processes that take too much time and get stuck, we put a
# 10 min timeout.
MAX_TIMEOUT = 10*60

# --- Worker function to process a single APK ---
def process_apk(apk_file):
    try:
        subfolder_name, pkg_name = apk_file.removesuffix('.apk').split('/', 1)
    except ValueError:
        return None

    hash_value = pkg2hash.get(pkg_name)
    if not hash_value:
        return None

    # Only process if this hash is in our explicit list and not already seen
    if hash_value in skipped_hashes and hash_value not in seen:
        apk_path = os.path.join(APK_DIR_PATH, apk_file)
        inline_code = f"""
import os, json
from quark.report import Report
apk_path = {repr(apk_path)}
RULE_DIR = {repr(RULE_DIR)}
OUTPUT_DIR = {repr(QUARK_RESCAN_PATH)}
subfolder_name = {repr(subfolder_name)}
report = Report()
report.analysis(apk_path, RULE_DIR)
json_report = report.get_report("json")
report_path = os.path.join(OUTPUT_DIR, subfolder_name, json_report['md5'] + '.json')
os.makedirs(os.path.dirname(report_path), exist_ok=True)
with open(report_path, 'w') as file:
    json.dump(json_report, file, indent=4)
"""
        start = time.monotonic()
        try:
            subprocess.run(
                [sys.executable, "-c", inline_code],
                timeout=MAX_TIMEOUT,
                check=True
            )
            status = "scanned"
            elapsed = time.monotonic() - start
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            status = "timeout"
            print(f"[T] Timeout after {MAX_TIMEOUT}s for {apk_file}")
        except subprocess.CalledProcessError as e:
            elapsed = time.monotonic() - start
            status = "error"
            print(f"[E] Error while processing {apk_file}: {e}")
        return (hash_value, status, elapsed)
    return None


# --- Main process with graceful cleanup on keyboard interrupt ---
def main():
    scanned_n = 0
    fail_n = 0
    timeout_n = 0

    pool = multiprocessing.Pool(processes=MAX_WORKERS)
    try:
        for result in pool.imap_unordered(process_apk, apk_files):
            if result:
                hash_value, status, elapsed = result
                seen.add(hash_value)
                
                # Add the file to the checkpoint file
                with open(CHECKPOINT_FILE_PATH, 'a') as cf:
                    cf.write(hash_value + "\n")
                    
                # Report unsuccessful scan results
                if status == 'scanned':
                    scanned_n += 1
                    print(f"[S] {hash_value} scanned")
                elif status == "timeout":
                    timeout_n += 1
                    with open(TIMEOUT_FILE_PATH, 'a') as tf:
                        tf.write(f'[T] {hash_value} {elapsed}\n')
                    print(f"[T] {hash_value} timed out")
                else:
                    fail_n += 1
                    with open(ERROR_FILE_PATH, 'a') as tf:
                        tf.write(f'[E] {hash_value} {elapsed}\n')
                    print(f"[E] {hash_value} failed")
        pool.close()
        pool.join()

    except KeyboardInterrupt:
        print("KeyboardInterrupt detected. Terminating pool and cleaning up...")
        pool.terminate()
        pool.join()
        sys.exit(1)

    print(f"[Summary] Scanned: {scanned_n}; Timeout: {timeout_n}; Failures: {fail_n}")


if __name__ == "__main__":
    # --- Build full sets of hashes and determine which are skipped ---
    all_hashes = set()
    for subfolder in Path(JSON_FILES_PATH).glob('eapks*'):
        if subfolder.is_dir():
            for json_file in subfolder.glob('*.json'):
                all_hashes.add(json_file.stem)

    print(f'Number of all hashes: {len(all_hashes)}')

    qk_hashes = set()
    for f in Path(QUARK_FST_SCAN_PATH).glob('eapks*/*.json'):
        qk_hashes.add(f.stem)

    print(f'Number of scanned hashes: {len(qk_hashes)}')

    skipped_hashes = all_hashes - qk_hashes
    print(f'Number of skipped hashes: {len(skipped_hashes)}')

    # --- Load or initialize required data structures ---
    with open('saved_pkg2hash.pkl', 'rb') as f:
        pkg2hash = pickle.load(f)

    if os.path.exists(CHECKPOINT_FILE_PATH):
        with open(CHECKPOINT_FILE_PATH) as f:
            seen = set(f.read().splitlines())
    else:
        seen = set()

    # --- Build your APK file list once ---
    if os.path.exists('saved_apk_files.pkl'):
        with open('saved_apk_files.pkl', 'rb') as f:
            apk_files = pickle.load(f)
    else:
        apk_files = []
        for subfolder in Path(APK_DIR_PATH).glob('eapks*'):
            if '_' not in subfolder.name:
                for f_path in subfolder.glob('*.apk'):
                    apk_files.append(os.path.join(subfolder.name, f_path.name))
        with open('saved_apk_files.pkl', 'wb') as f:
            pickle.dump(apk_files, f)

    # Pre‑filter apk_files in the main process
    to_scan = []
    for apk_file in apk_files:
        # strip “.apk” and split into subfolder/pkg
        name = apk_file[:-4] if apk_file.endswith('.apk') else apk_file
        try:
            subfolder_name, pkg_name = name.split('/', 1)
        except ValueError:
            continue

        hash_value = pkg2hash.get(pkg_name)
        if hash_value in skipped_hashes and hash_value not in seen:
            to_scan.append(apk_file)

    print(f"Will (re)scan {len(to_scan)} APKs …")
    apk_files = to_scan

    main()