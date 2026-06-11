import csv
from pprint import pprint

PKG_NAME_FILE = '/shared/frankzha/apkfile_names_870.txt'
PKG_MAP_FILE = '/shared/henrysfiles/Android-Data/Hash Calculation/md5_hashes.csv'

DATA_FILE = '/shared/frankzha/data/hash/hashes.csv'
CHECKPOINT_FILE = '/shared/frankzha/data/hash/processed.txt'

n = 0  # Number of new hashes added
pkg2row = {}  # Stores a mapping between all the package names to their hashes, folder, etc.
with (open(PKG_MAP_FILE) as map_file,
      open(PKG_NAME_FILE) as pkg_file,
      open(CHECKPOINT_FILE, 'r+') as cp_file,
      open(DATA_FILE, 'a') as data_file):
    map_reader = csv.reader(map_file)
    data_writer = csv.writer(data_file)
    
    # copies the header over to allow submit_to_virustotal_report.py
    # to use csv.DictReader to read the file
    fieldnames = next(map_reader)
    data_writer = csv.DictWriter(data_file, fieldnames=fieldnames)
    for row in map_reader:
        pkg2row[row[1]] = dict(zip(fieldnames, row))
    
    # pprint(list(pkg2row.items())[:10])
    
    next(pkg_file)  # Skip the first line (it's just "pkgname")
    pkgs = pkg_file.read().splitlines()
    processed = set(cp_file.read().splitlines())
    for pkg in pkgs:
        pkg_name = pkg + '.apk'
        if pkg_name in processed:
            continue

        # Write to hash file
        try:
            data_writer.writerow(pkg2row[pkg_name])
            # Update checkpoint file
            cp_file.write(pkg_name + '\n')
            n += 1
        except KeyError:
            print(f'{pkg_name} is not found!')
    
print(f'Done! Added {n} new hashes.')