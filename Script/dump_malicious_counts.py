import pickle
import json
from pathlib import Path

api_json_files = list(Path('/shared/frankzha/data/_past_json_reports/json_reports').glob('eapks*/*.json'))
print('Finished 1')
harmful = []
for f in api_json_files:
    r = f.read_text()
    stats_idx = r.find('}{"stats"') + 1
    stats = json.loads(r[stats_idx:])['stats']
    harmful.append(stats['suspicious'] + stats['malicious'])
print('Finished 2')
with open('saved_malicious_counts.pkl', 'wb') as f:
    pickle.dump(harmful, f)
print('Finished 3')
    