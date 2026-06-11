import csv
import pickle
from pprint import pprint

# com.catdaddy.cat22


PKG_MAP_FILE = '/shared/henrysfiles/Android-Data/Hash Calculation/md5_hashes.csv'

n = 0
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


print(f'length: {len(pkg2hash)}')
n = 0
for p, h in pkg2hash.items():
    if n == 5:
        break
    n += 1
    print(f'pkg: {p}, hash: {h}')

with open('saved_pkg2hash.pkl', 'wb') as f:
    pickle.dump(pkg2hash, f)
    