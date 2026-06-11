import os, json
from pathlib import Path


QUARK_PATH = "/shared/frankzha/data/quark_engine_results"
VT_PATH = "/shared/frankzha/data/new_json_reports_ai/"

JSON_FILES_PATH = '/shared/frankzha/data/_past_json_reports/json_reports'

all_hashes = set()
for subfolder in Path(JSON_FILES_PATH).glob('eapks*'):
    if subfolder.is_dir():
        for json_file in subfolder.glob('*.json'):
            all_hashes.add(json_file.stem)

print(f'Number of all hashes: {len(all_hashes)}')

qk_hashes = set()   # set of hashes scanned by Quark-engine
for f in Path(QUARK_PATH).glob('eapks*/*.json'):
    filename = os.path.basename(f.name)
    qk_hashes.add(filename[:-5])

print(f'Number of scanned hashes: {len(qk_hashes)}')     
                
skipped_hashes = all_hashes - qk_hashes
print(f'Number of skipped hashes: {len(skipped_hashes)}')

scanned_size = scanned_n = 0
skipped_size = skipped_n = 0
error_n = 0

for f in list(Path(VT_PATH).glob('eapks*/*.json')):
    fname = os.path.basename(f.name)
    with f.open("r", encoding='utf-8') as file:
        try:
            vt_report = json.load(file)
        except json.decoder.JSONDecodeError:
            continue
        
    attrs = vt_report.get('data', {}).get('attributes', {})
    file_size = attrs.get('size', None)
    
    if file_size is None:
        error_n += 1
    else:
        if fname[:-5] in skipped_hashes:
            skipped_size += file_size
            skipped_n += 1
        else:
            scanned_size += file_size
            scanned_n += 1    
    
print(f'Number of files without size info: {error_n}')
print(f'Average file size of scanned files: {(mean_scanned_fsize := scanned_size/scanned_n)}')
print(f'Average file size of skipped files: {(mean_skipped_fsize := skipped_size/skipped_n)}')
print('Average percent difference is: '
      f'{(mean_skipped_fsize - mean_scanned_fsize) / mean_scanned_fsize * 100:.3f}%')

