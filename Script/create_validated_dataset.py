import csv
from os.path import join as pjoin
from tqdm import tqdm

from utility import load_pkg2hash, load_hash2malicious, load_hash2risk, get_reliable_vt_ai_files, get_all_vt_ai_files

# change to get_reliable_vt_ai_files?

# original/paper dataset: Removed vs. Non-removed
# VirusTotal dataset: Malicious (>= threshold) vs. Benign

DATASET_DIR = '/shared/frankzha/data/datasets'

PAPER_PATH = '/shared/evanroot/manifests_dir/paper_replication/corrected_permacts.csv'
PAPER_SUMMARY_DATASET_FILE = '/shared/frankzha/data/datasets/paper_summary_dataset.csv'

STATUS_INDEX = 34   # index of the status (whether the app is removed or not)


# a = get_all_vt_ai_files()
# b = get_reliable_vt_ai_files()
# print(len(a), len(b))

reli_vt_hashes: set[str] = {f.stem for f in get_reliable_vt_ai_files()}
print(next(iter(reli_vt_hashes)))
print(len(reli_vt_hashes))

p2h = load_pkg2hash()
h2r = load_hash2risk()
h2m = load_hash2malicious()
print(f'{len(p2h)=}, {len(h2r)=}, {len(h2m)=}')


for threshold in range(1, 5+1):
    n = 0
    vt_file = 0
    qk_file = 0
    def_benign_n = 0
    def_malicious_n = 0
    print(f'When {threshold = }:')
    # r = {'low': 0, 'moderate': 0, 'high': 0}
    
    dataset_path = pjoin(DATASET_DIR, f'val_dataset_t{threshold}.csv')
    print(f'Create dataset with {threshold = } at {dataset_path}')
    
    with open(PAPER_SUMMARY_DATASET_FILE, 'r') as paper_summary,\
          open(dataset_path, 'w+') as dataset:
        # paper_reader = csv.reader((line.replace('\0','') for line in paper_f), delimiter=",")
        
        ps_reader = csv.reader(paper_summary, delimiter=',')
        ds_writer = csv.writer(dataset)        
        ds_writer.writerow(next(ps_reader) + ['verdict'])
        
        for row in tqdm(ps_reader, total=772533, desc="Compiling validated dataset", unit="file"):
            pkg_name = row[1]
            try:
                md5_hash = p2h[pkg_name]
            except KeyError:
                continue
                         
            if md5_hash in h2m and md5_hash in h2r and md5_hash in reli_vt_hashes:
                # r[h2r[md5_hash]] += 1
                
                n += 1
                benign_by_paper = row[STATUS_INDEX] == '0'  # non-removed
                benign_by_vt = h2m[md5_hash] < threshold    # benign   
                benign_by_qk = h2r[md5_hash] == 'low'       # low rish
                
                def_benign = benign_by_paper and benign_by_vt and benign_by_qk
                def_malicious = not benign_by_paper and not benign_by_vt and not benign_by_qk
                
                if def_benign:
                    def_benign_n += 1
                    ds_writer.writerow(row + ['benign'])
                    
                elif def_malicious:
                    def_malicious_n += 1
                    ds_writer.writerow(row + ['malicious'])
                
                
        print(f'Total number of valid files: {n}')
        print(f'Total number of files that are definitely benign: {def_benign_n} ({def_benign_n/n:.3%})')
        print(f'Total number of files that are definitely malicious: {def_malicious_n} ({def_malicious_n/n:.3%})')
            

# {'low': 70010, 'moderate': 702401, 'high': 95}