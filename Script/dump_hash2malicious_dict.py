import pickle
import json
from pathlib import Path


JSON_FILES_PATH = '/shared/frankzha/data/_past_json_reports/json_reports'


hash2malicious = {}
for f in list(Path(JSON_FILES_PATH).glob('eapks*/*.json')):
    r = f.read_text()
    stats_idx = r.find('}{"stats"') + 1
    stats = json.loads(r[stats_idx:])['stats']
    hash2malicious[f.name[:-5]] = stats['suspicious'] + stats['malicious']
    
    
with open('saved_hash2malicious.pkl', 'wb') as f:
    pickle.dump(hash2malicious, f)