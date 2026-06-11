import os
import sys
import json
import pickle
import subprocess
from pathlib import Path
import multiprocessing

# --- Global configuration ---
APK_DIR_PATH = '/mnt/data/Android-Data/APKs'
RULE_DIR = '/home/umflint.edu/frankzha/.quark-engine/quark-rules/rules'
JSON_FILES_PATH = '/shared/frankzha/data/_past_json_reports/json_reports'
CHECKPOINT_FILE_PATH = '/shared/frankzha/data/quark_engine_results/qk_fst_scan/quark_checkpoint.txt'
TIMEOUT_FILE_PATH = '/shared/frankzha/data/quark_engine_results/qk_fst_scan/quark_timeout.txt'
OUTPUT_DIR = "/shared/frankzha/data/quark_engine_results/qk_fst_scan"
TIMEOUT_IN_SEC = 2*60

# --- Load or initialize required data structures ---
with open('saved_pkg2hash.pkl', 'rb') as f:
    pkg2hash = pickle.load(f)

if os.path.exists(CHECKPOINT_FILE_PATH):
    with open(CHECKPOINT_FILE_PATH) as f:
        seen = set(f.read().splitlines())
else:
    seen = set()

hashes = set()
for subfolder in Path(JSON_FILES_PATH).glob('eapks*'):
    if subfolder.is_dir():
        for json_file in subfolder.glob('*.json'):
            hashes.add(json_file.stem)

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

print("pkg2hash entries:", len(pkg2hash))
print("JSON hashes:", len(hashes))
print("APK files:", len(apk_files))

# --- Worker function to process a single APK ---
def process_apk(apk_file):
    try:
        subfolder_name, pkg_name = apk_file.removesuffix('.apk').split('/', 1)
    except ValueError:
        # Skip files that don't match the expected pattern.
        return None

    hash_value = pkg2hash.get(pkg_name)
    if not hash_value:
        return None

    # Only process if the hash appears in the JSON reports and is not seen yet.
    if hash_value in hashes and hash_value not in seen:
        apk_path = os.path.join(APK_DIR_PATH, apk_file)
        # Build inline Python code to run the analysis.
        inline_code = f"""
import os, json
from quark.report import Report
apk_path = {repr(apk_path)}
RULE_DIR = {repr(RULE_DIR)}
OUTPUT_DIR = {repr(OUTPUT_DIR)}
subfolder_name = {repr(subfolder_name)}
report = Report()
report.analysis(apk_path, RULE_DIR)
json_report = report.get_report("json")
report_path = os.path.join(OUTPUT_DIR, subfolder_name, json_report['md5'] + '.json')
os.makedirs(os.path.dirname(report_path), exist_ok=True)
with open(report_path, 'w') as file:
    json.dump(json_report, file, indent=4)
"""
        try:
            subprocess.run([sys.executable, "-c", inline_code],
                           timeout=TIMEOUT_IN_SEC,
                           check=True)
            status = "scanned"
        except subprocess.TimeoutExpired:
            print(f'[TO] {hash_value} timed out')
            status = "timeout"
        except subprocess.CalledProcessError as e:
            if e.returncode == -9:
                print(f'[TO] {hash_value} timed out (SIGKILL)')
                status = "timeout"
            else:
                print(f"[E] Error while processing {apk_file}: {e}")
                status = "error"
        return (hash_value, status)
    return None

# --- Main process with graceful cleanup on keyboard interrupt ---
def main():
    scanned = 0
    timeouts = 0
    errors = 0

    pool = multiprocessing.Pool()
    try:
        # Process APK files as soon as results are available.
        for result in pool.imap_unordered(process_apk, apk_files):
            if result is not None:
                hash_value, status = result
                seen.add(hash_value)
                
                with open(CHECKPOINT_FILE_PATH, 'a') as cf:
                    cf.write(hash_value + "\n")
                
                if status == "timeout":
                    with open(TIMEOUT_FILE_PATH, 'a') as tf:
                        tf.write(hash_value + "\n")
                if status == "scanned":
                    scanned += 1
                    # Print success message when a file is scanned.
                    print(f"[S] {hash_value} scanned")
                elif status == "timeout":
                    timeouts += 1
                elif status == "error":
                    errors += 1
        pool.close()
        pool.join()
    except KeyboardInterrupt:
        print("KeyboardInterrupt detected. Terminating pool and cleaning up...")
        pool.terminate()
        pool.join()
        sys.exit(1)

    # Print a summary of results.
    print(f"Summary -> Scanned: {scanned}, Timeouts: {timeouts}, Errors: {errors}")

if __name__ == "__main__":
    main()


"""
len(qk_hashes)=772733
len(paper_hashes)=870511
len(paper_hashes & qk_hashes)=772732
{'602bebf021aabb6fcadd0ec8e322f116'}
len(apk_files)=1389499
['eapks10/a.accelerodraw.apk', 'eapks10/a.b.see.apk', 'eapks10/a.com.Company.ProductName.apk', 'eapks10/a.games.apk', 'eapks10/a.helloworld.apk', 'eapks10/a.kakao.KNH.Spring.apk', 'eapks10/a.mini.calculator.apk', 'eapks10/a.mjtest.apk', 'eapks10/a.r.mywatchlist.apk', 'eapks10/a.simplymirror.apk']
/shared/frankzha/data/quark_engine_results/qk_rescan/eapks9/602bebf021aabb6fcadd0ec8e322f116.json
"""