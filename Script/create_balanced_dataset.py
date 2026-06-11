import re
import csv
import os
from pathlib import Path
import json
import matplotlib.pyplot as plt
import pickle

# Setting
THRESHOLD = 5   # threshold = min $ of scanners for a malicious file; see below
"""
When threshold = 5:
 - Benign and non-removed files: 345219
 - Malicious and removed files: 21418
"""

# Path constants for files
PAPER_PATH = '/shared/evanroot/manifests_dir/paper_replication/corrected_permacts.csv'

STATUS_INDEX = 34   # index of the status (whether the app is removed or not)
VT_PATH = "/shared/frankzha/data/new_json_reports_ai/"

# Path constants for cached hash-package conversion
PKG_MAP_FILE = '/shared/henrysfiles/Android-Data/Hash Calculation/md5_hashes.csv'

SIZE = None     # default = size of the malicious sample (which is the limiting factor)


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
    for fname in list(Path(VT_PATH).glob('eapks*/*.json')):
        with fname.open("r", encoding='utf-8') as f:
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
       
print('[1] Finished collecting statistics')






"""
for threshold in range(1, 10+1):
    n = 0
    benign_nr = 0
    malicious_r = 0
    print(f'When {threshold = }:')
    with open(PAPER_PATH, 'r') as paper_f:
        paper_reader = csv.reader((line.replace('\0','') for line in paper_f), delimiter=",")
        next(paper_reader)
        
        
        for row in paper_reader:            
            pkg_name = row[1]
            paper_verdict = 'non-removed' if row[STATUS_INDEX] == '0' else 'removed'
            
            try:
                md5_hash = pkg2hash[pkg_name]
            except KeyError:
                continue
            
            try:
                malicious_cnt = hash2malicious[md5_hash]
                if malicious_cnt >= threshold:
                    vt_verdict = 'malicious'
                else:
                    vt_verdict = 'benign'
                    
            except KeyError:
                continue
            
            n += 1
            
            if vt_verdict == 'benign' and paper_verdict == 'non-removed':
                benign_nr += 1
            elif vt_verdict == 'malicious' and paper_verdict == 'removed':
                malicious_r += 1

        print(f'- Benign and non-removed files: {benign_nr}')
        print(f'- Malicious and removed files: {malicious_r}')
        
print(f'Total: {n}')
"""