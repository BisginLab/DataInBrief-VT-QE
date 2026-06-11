import csv
from pathlib import Path
import json
import matplotlib.pyplot as plt
import pickle 


# min # of scanners that label a file malicious
# in order for it to be considered malicious
THRESHOLD = 1

PAPER_PATH = '/shared/evanroot/manifests_dir/paper_replication/corrected_permacts.csv'
STATUS_INDEX = 34   # index of the status (whether the app is removed or not)
JSON_FILES_PATH = '/shared/frankzha/data/_past_json_reports/json_reports'

# Cache the mapping from package name to hash values and the mapping from
# hash value to malicious counts to save time
with open('saved_pkg2hash.pkl', 'rb') as f:
    pkg2hash = pickle.load(f)


with open('saved_hash2malicious.pkl', 'rb') as f:
    hash2malicious = pickle.load(f)

print(len(hash2malicious))
print('[1] Finished collecting malicious counts')


"""[Note 1] Quote from the paper:
A value of 1 means the app was not in the market on the indicated date,
0 means otherwise.

paper link: https://arxiv.org/abs/2206.03905

i.e., 1 = removed, 0 = not removed
"""
"""[Note 2] Difference in the number of verdicts
The paper replication folder has 870515 verdicts while our
current approach has 803534 valid API responses.
"""
"""[Note 3] Errors in matching
gr.itravelguides.lesvos (package name) is the ONLY one that cannot be matched to any hash value
"""

n = 1
fail_match_pkg2hash = fail_match_hash2malicious = 0
both_removed = both_nonremoved = 0
removed2nonremoved = nonremoved2removed = 0

b = 0

with open(PAPER_PATH, 'r') as f:
    reader = csv.reader((line.replace('\0','') for line in f), delimiter=",")
    next(reader)
    for row in reader:
        n += 1
        pkg_name = row[1]
        paper_verdict = row[STATUS_INDEX]
        
        curr_verdict = '0'
        try:
            hash_value = pkg2hash[pkg_name]
        except KeyError:
            fail_match_pkg2hash += 1
            continue
        
        try:
            malicious_cnt = hash2malicious[hash_value]
            if malicious_cnt >= THRESHOLD:
                curr_verdict = '1'
            
        except KeyError:
            fail_match_hash2malicious += 1
            continue
        if curr_verdict == '1':
            b += 1
        if paper_verdict == '0' and curr_verdict == '0':
            both_nonremoved += 1
        elif paper_verdict == '1' and curr_verdict == '1':
            both_removed += 1
        elif paper_verdict == '0' and curr_verdict == '1':
            nonremoved2removed += 1
        else:
            removed2nonremoved += 1
        
print(fail_match_hash2malicious)
print('b', b)
print(f'Not removed by both paper and our approach: {both_nonremoved}')
print(f'Removed by both paper and our approach: {both_removed}')
print(f'Not removed by paper but removed by our approach: {nonremoved2removed}')
print(f'Removed by paper but not removed by our approach: {removed2nonremoved}')

print('[3] Finished collecting past verdicts')

