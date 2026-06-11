import pandas as pd
import csv
from tqdm import tqdm

from utility import load_pkg2hash, PAPER_FILE

SUMMARY_DATASET_FILE = '/shared/frankzha/data/datasets/summary_dataset.csv'
PAPER_SUMMARY_DATASET_FILE = '/shared/frankzha/data/datasets/paper_summary_dataset.csv'

pkg2hash = load_pkg2hash()

# Build a map from hash values (1st column in the summary dataset) to 10 features
hash2features = {}
with open(SUMMARY_DATASET_FILE, newline="") as file:
    summary_reader = csv.reader(file)
    summary_header = next(summary_reader)
    
    for row in summary_reader:
        hash_value = row[0]
        features = row[1:]
        hash2features[hash_value] = features

print('Start')
with (open(PAPER_SUMMARY_DATASET_FILE, 'w', newline="") as ps_file,
      open(PAPER_FILE, newline='') as paper_file):
    ps_writer = csv.writer(ps_file, delimiter=",")
    paper_reader = csv.reader((line.replace('\0','') for line in paper_file), delimiter=",")
    
    # Write the header
    paper_header = next(paper_reader)
    ps_writer.writerow(paper_header + summary_header[1:])   # Exclude the md5
    
    # Write the rows
    row_n = match_n = 1   # start from 1 to account for the header rows
    for row in tqdm(paper_reader):
        row_n += 1
        pkg_name = row[1]
        if hash_value := pkg2hash.get(pkg_name):
            if features := hash2features.get(hash_value):
                match_n += 1
                ps_writer.writerow(row + features)

print(f'All {row_n} rows have been processed!')
print(f'Created CSV file with {match_n} rows.')

# All 870515 rows have been processed!
# Created CSV file with 736427 rows.


import pandas as pd
ps_dataset = pd.read_csv(PAPER_SUMMARY_DATASET_FILE)
print(f'Number of rows: {len(ps_dataset)}')
print(f'Number of columns: {len(ps_dataset.columns)}')