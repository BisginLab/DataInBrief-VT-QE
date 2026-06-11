import re
import csv
import os
from pathlib import Path
import json
import matplotlib.pyplot as plt
import pickle

# Path constants for files
PAPER_PATH = '/shared/evanroot/manifests_dir/paper_replication/corrected_permacts.csv'

STATUS_INDEX = 34   # index of the status (whether the app is removed or not)
QUARK_PATH = "/shared/frankzha/data/quark_engine_results"
VT_PATH = "/shared/frankzha/data/new_json_reports_ai/"

REPORT_FILE_PATH = '/shared/frankzha/data/aggregated_report.csv'

# Path constants for cached hash-package conversion
PKG_MAP_FILE = '/shared/henrysfiles/Android-Data/Hash Calculation/md5_hashes.csv'

# Cache the mappings
p2h_filename = 'saved_cs_pkg2hash.pkl'
if os.path.exists(p2h_filename):
    with open(p2h_filename, 'rb') as f:
        pkg2hash = pickle.load(f)
else:
    pkg2hash = {}  # Stores a mapping between all the package names to their hashes, folder, etc.
    with open(PKG_MAP_FILE) as map_file:
        map_reader = csv.reader(map_file)
        fieldnames = next(map_reader)
        for row in map_reader:
            pkg_name = row[1]
            hash_value = row[2]
            if pkg_name[-4:] == '.apk':
                pkg_name = pkg_name[:-4]
            pkg2hash[pkg_name] = hash_value

    with open(p2h_filename, 'wb') as f:
        pickle.dump(pkg2hash, f)

print(f'[1.1] Finished collecting {len(pkg2hash)} package-to-hash relations')

h2m_filename = 'saved_cs_hash2malicious.pkl'
if os.path.exists(h2m_filename):
    with open(h2m_filename, 'rb') as f:
        hash2malicious = pickle.load(f)
else:
    hash2malicious = {}
    for f in list(Path(VT_PATH).glob('eapks*/*.json')):
        with f.open("r", encoding='utf-8') as f:
            try:
                vt_report = json.load(f)
            except json.decoder.JSONDecodeError:
                continue
        
        attr = vt_report.get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        malicious = stats.get('malicious')
        filename = os.path.basename(f.name)
        hash2malicious[filename[:-5]] = malicious
        
    with open(h2m_filename, 'wb') as f:
        pickle.dump(hash2malicious, f)
        
print(f'[1.2] Finished collecting {len(hash2malicious)} hash-to-malicious relations')
       
h2r_filename = 'saved_cs_hash2risk.pkl'
if os.path.exists(h2r_filename):
    with open(h2r_filename, 'rb') as f:
        hash2risk = pickle.load(f)
else:
    hash2risk = {}
    for f in Path(QUARK_PATH).glob('eapks*/*.json'):
        # with f.open("r", encoding='utf-8') as f:
        #     try:
        #         quark_report = json.load(f)
        #     except json.decoder.JSONDecodeError:
        #         continue
        threat_level_match = re.search(r'"threat_level":\s*"([^"]+)"', f.read_text())
        if threat_level_match:
            filename = os.path.basename(f.name)
            threat_level = threat_level_match.group(1)
            hash2risk[filename[:-5]] = threat_level.split()[0].lower()

    with open(h2r_filename, 'wb') as f:
        pickle.dump(hash2risk, f)
        
print(f'[1.3] Finished collecting {len(hash2risk)} hash-to-risk counts')

print('[1] Finished collecting statistics')


n = 0
fail_count = 0
both_removed = both_nonremoved = 0
removed2nonremoved = nonremoved2removed = 0


headers = [
    "md5_hash", "pkg_name", 
    "quark_verdict", "vt_verdict", "paper_verdict"
]

with (open(PAPER_PATH, 'r') as paper_f,
      open(REPORT_FILE_PATH, mode="w", newline="") as report_f):
    paper_reader = csv.reader((line.replace('\0','') for line in paper_f), delimiter=",")
    next(paper_reader)
    
    report_writer = csv.DictWriter(report_f, fieldnames=headers)
    report_writer.writeheader()
    
    for row in paper_reader:
        n += 1
        pkg_name = row[1]
        paper_verdict = 'non-removed' if row[STATUS_INDEX] == '0' else 'removed'
        
        try:
            md5_hash = pkg2hash[pkg_name]
        except KeyError:
            fail_count += 1
            continue
        
        try:
            malicious_cnt = hash2malicious[md5_hash]
            if malicious_cnt == 0:
                vt_verdict = 'benign'
            elif malicious_cnt == 1:
                vt_verdict = 'borderline'
            else:
                vt_verdict = 'malicious'
                
        except KeyError:
            fail_count += 1
            continue
            
        try:
            quark_verdict = hash2risk[md5_hash]                
        except KeyError:
            fail_count += 1
            continue

        row = {
            "md5_hash": md5_hash,
            "pkg_name": pkg_name,
            "quark_verdict": quark_verdict,
            # low, moderate, high
            "vt_verdict": vt_verdict,
            # benign, borderline (1 scanner w/ malicious verdicts), risky (>1 scanners w/ malicious verdicts)
            "paper_verdict": paper_verdict
            # removed vs. non-removed
        }

        report_writer.writerow(row)

                
print(f'Fail count: {fail_count}')
print(f'Success count: {n - fail_count}')
print('[2] Finished creating the file')