from utility import *
from tqdm import tqdm
import csv
from pathlib import Path
from multiprocessing import Pool

print(f'{len(get_all_vt_ai_files())=}')
print(f'{len(get_qk_files())=}')

print(f'fst scan: {len(set(Path(QUARK_FST_SCAN_DIR).rglob('*.json')))}')
print(f'rescan: {len(set(Path(QUARK_RESCAN_DIR).rglob('*.json')))}')

# --- Config ---
HASH_CSV = "/shared/frankzha/data/hash/hashes.csv"

# --- Shared lookup set ---
qk_hashes = {f.stem for f in get_qk_files()}

def process_row(row):
    """
    Returns a 4‑tuple:
      (scanned_count, scanned_size, skipped_count, skipped_size)
    """
    folder, pkg, md5 = row
    size = (Path(APK_DIR) / folder / pkg).stat().st_size
    if md5 in qk_hashes:
        return (1, size, 0, 0)
    else:
        return (0, 0, 1, size)

# --- Read all rows once (skip header) ---
with open(HASH_CSV, newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    next(reader)
    rows = list(reader)

# --- Initialize counters ---
scanned_n = scanned_sz = skipped_n = skipped_sz = 0

# --- Parallel map, updating counters on the fly ---
with Pool(8) as pool:
    for s_n, s_sz, sk_n, sk_sz in tqdm(pool.imap(process_row, rows),
                                       total=len(rows),
                                       desc="Processing paper hash"):
        scanned_n   += s_n
        scanned_sz  += s_sz
        skipped_n   += sk_n
        skipped_sz  += sk_sz

# --- Final report ---
print(f"Scanned {scanned_n} files "
      f"with an average size of {scanned_sz/scanned_n:.3f} bytes")
print(f"Skipped {skipped_n} files "
      f"with an average size of {skipped_sz/skipped_n:.3f} bytes")





"""
vt_files = path2names(get_all_vt_ai_files())
print(next(iter(vt_files)))
print('602bebf021aabb6fcadd0ec8e322f116.json' in vt_files)
print('c1dc3f365ff5013e5a2f45983a36b6c2.json' in vt_files)
print(any('602bebf021aabb6fcadd0ec8e322f116' in f for f in vt_files))

print('602bebf021aabb6fcadd0ec8e322f116.json' in path2names(Path(QUARK_FST_SCAN_DIR).rglob('*.json')))
print('602bebf021aabb6fcadd0ec8e322f116.json' in path2names(Path(QUARK_RESCAN_DIR).rglob('*.json')))
"""
# a = None

# for qk_f in Path(QUARK_RESCAN_DIR).rglob('*.json'):
#     if qk_f.stem == '602bebf021aabb6fcadd0ec8e322f116':
#         a = qk_f.absolute()
        
# import os
# os.remove(a)
    
# os.path.join(APK_DIR, 

# 7/31
# 8/29

"""
import json
from pathlib import Path


QUARK_PATH        = "/shared/frankzha/data/quark_engine_results"
VT_PATH           = "/shared/frankzha/data/new_json_reports_ai/"
JSON_FILES_PATH   = "/shared/frankzha/data/_past_json_reports/json_reports"

# 1) Gather all known hashes
all_hashes = {
    p.stem
    for p in Path(JSON_FILES_PATH).glob("eapks*/*.json")
}
print(f"Number of all hashes: {len(all_hashes)}")

# 2) Hashes scanned by Quark
qk_hashes = {
    p.stem
    for p in Path(QUARK_PATH).glob("eapks*/*.json")
}
print(f"Number of scanned hashes: {len(qk_hashes)}")

# 3) Hashes skipped by Quark
skipped_hashes = all_hashes - qk_hashes
print(f"Number of skipped hashes: {len(skipped_hashes)}")

# 4) Accumulate sizes
scanned_size = scanned_n = 0
skipped_size = skipped_n = 0
error_n = 0

for report_path in Path(VT_PATH).glob("eapks*/*.json"):
    stem = report_path.stem
    with report_path.open("r", encoding="utf-8") as fh:
        try:
            vt_report = json.load(fh)
        except json.decoder.JSONDecodeError:
            error_n += 1
            continue

    size = (
        vt_report
        .get("data", {})
        .get("attributes", {})
        .get("size")
    )
    if size is None:
        error_n += 1
        continue

    if stem in skipped_hashes:
        skipped_size += size
        skipped_n += 1
    else:
        scanned_size += size
        scanned_n += 1

# 5) Compute averages (guard for zero)
avg_scanned = scanned_size / scanned_n if scanned_n else 0
avg_skipped = skipped_size / skipped_n if skipped_n else 0

print(f"Average file size of scanned files: {avg_scanned:.2f} bytes")
print(f"Average file size of skipped files: {avg_skipped:.2f} bytes")
print(f"Number of files with JSON errors or missing size: {error_n}")

# 6) Percent difference
if scanned_n and skipped_n:
    percent_diff = (avg_skipped - avg_scanned) / avg_scanned * 100
    print(f"Skipped files are {percent_diff:.2f}% larger than scanned files.")
else:
    print("Not enough data to compute percent difference.")
"""


"""
len(qk_hashes)=772733
len(paper_hashes)=870511
len(paper_hashes & qk_hashes)=772732
{'602bebf021aabb6fcadd0ec8e322f116'}
len(apk_files)=1389499
['eapks10/a.accelerodraw.apk', 'eapks10/a.b.see.apk', 'eapks10/a.com.Company.ProductName.apk', 'eapks10/a.games.apk', 'eapks10/a.helloworld.apk', 'eapks10/a.kakao.KNH.Spring.apk', 'eapks10/a.mini.calculator.apk', 'eapks10/a.mjtest.apk', 'eapks10/a.r.mywatchlist.apk', 'eapks10/a.simplymirror.apk']
/shared/frankzha/data/quark_engine_results/qk_rescan/eapks9/602bebf021aabb6fcadd0ec8e322f116.json
"""