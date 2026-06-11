import os, json, pickle

from pathlib import Path
from utility import get_all_vt_ai_files, get_reliable_vt_ai_files

VT_PATH = "/shared/frankzha/data/new_json_reports_ai/"

print(f'{len(get_all_vt_ai_files())=}, {len(get_reliable_vt_ai_files())=}')
# eapks5/ae30f17783957bfc8417b0854c9b0023.json
truly_benign_n = fst_time_benign_n = 0
fst_time_benign_hashes = set()
wtf = 0

# for f in get_reliable_vt_ai_files():
#     with f.open("r", encoding='utf-8') as file:
#         try:
#             vt_report = json.load(file)
#         except json.decoder.JSONDecodeError:
#             continue
    
#     attrs = vt_report.get('data', {}).get('attributes', {})
#     times = attrs.get("times_submitted")
#     mal_count = attrs.get('last_analysis_stats', {}).get("malicious")
    
#     if mal_count == 0:
#         # benign file
#         if times == 0:
#             fst_time_benign_n += 1
#             fst_time_benign_hashes.add(f.stem)
#         elif times == 1:
#             wtf += 1
#         else:
#             truly_benign_n += 1

# print(f'WTF lil bro: {wtf}')
# print(f'Number of truly benign files (times_submitted > 0): {truly_benign_n}')  # 700259
# print(f'Number of 1st time benign files (times_submitted = 0): {fst_time_benign_n}')    # 190

# # with open('fst_time_benign_hashes.pkl', "wb") as f:
# #     pickle.dump(fst_time_benign_hashes, f)
# #     print(f'1st time benign hashes include: {fst_time_benign_hashes}')
