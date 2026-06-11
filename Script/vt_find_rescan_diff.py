"""
[purpose]
I noticed that while the initial scan gathers 803537 VT responses (API V2),
the rescan gathers 803365 VT responses (API V3, includes far more info). Moreover,
they share 802914 hashes.

To close the gap, this script aims to scan 620 hashes that are in the initial scan
but not the rescan.

Result:
 - 610 hashes were successfully filled. However, 10 hashes were NOT FOUND
   (it is manually verified that they are indeed not on the VT platform).
 - Requesting those hashes result in HTTP 404.
"""

from pathlib import Path
import json

VT_OG_PATH = "/shared/frankzha/data/_past_json_reports/json_reports/"
VT_AI_PATH = "/shared/frankzha/data/new_json_reports_ai/"


# Map from hash value to folder
hash2folder = {}

def f(path: Path) -> str:
    folder = path.parent.name
    hash_ = path.stem
    hash2folder[hash_] = folder
    return hash_

vt_og_hashes = set(map(f, Path(VT_OG_PATH).rglob('eapks*/*.json')))
vt_ai_hashes = set(map(f, Path(VT_AI_PATH).rglob('eapks*/*.json')))

print(len(vt_og_hashes))  # 803537
print(len(vt_ai_hashes))  # 803365 (less)
print(len(vt_og_hashes & vt_ai_hashes))   # 802914

missed_hashes = vt_og_hashes - vt_ai_hashes
print(missed_hashes)
print(f'Need to scan {len(missed_hashes)} hashes')

# <----->

import aiohttp
import aiofiles
import asyncio
import os
import json
from datetime import datetime, timedelta, timezone

# ───> INPUT_LIST now contains only (folder, md5) tuples <───────────────────
INPUT_LIST = [
    ('folderA', '0123456789abcdef0123456789abcdef'),
    ('folderB', 'fedcba9876543210fedcba9876543210'),
    # …add more (folder, md5) pairs here…
]
# ──────────────────────────────────────────────────────────────────────────

# API_KEY = 'c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0'
# QUOTA_URL = 'https://www.virustotal.com/api/v3/users/{id}/overall_quotas'
# REPORT_URL_V3 = 'https://www.virustotal.com/api/v3/files/{id}'
# CHECKPOINT_FILE = '/shared/frankzha/data/new_processed_frank_ai.txt'
# JSON_OUTPUT_DIR = '/shared/frankzha/data/new_json_reports_ai/'

# def next_reset_time() -> datetime:
#     """Return the next occurrence of 00:01 UTC."""
#     now = datetime.now(timezone.utc)
#     tomorrow = now.date() + timedelta(days=1)
#     return datetime(
#         tomorrow.year,
#         tomorrow.month,
#         tomorrow.day,
#         hour=0,
#         minute=1,
#         tzinfo=timezone.utc
#     )

# '''
# async def read_checkpoint() -> set:
#     """Read processed MD5 hashes from checkpoint file."""
#     processed = set()
#     try:
#         async with aiofiles.open(CHECKPOINT_FILE, mode='r') as f:
#             async for line in f:
#                 processed.add(line.strip())
#     except FileNotFoundError:
#         pass
#     return processed
# '''

# async def write_checkpoint(md5: str):
#     """Append a processed MD5 to the checkpoint file."""
#     async with aiofiles.open(CHECKPOINT_FILE, mode='a') as f:
#         await f.write(f"{md5}\n")

# async def save_json_report(report: dict, folder: str, md5: str):
#     """Save the JSON report under the given folder."""
#     folder_path = os.path.join(JSON_OUTPUT_DIR, folder)
#     os.makedirs(folder_path, exist_ok=True)
#     file_path = os.path.join(folder_path, f"{md5}.json")
#     async with aiofiles.open(file_path, mode='w') as f:
#         await f.write(json.dumps(report))

# async def get_analysis(session: aiohttp.ClientSession, md5: str, folder: str):
#     """Fetch analysis report from VT and handle rate limits."""
#     # 1) Check daily quota
#     async with session.get(QUOTA_URL.format(id=API_KEY)) as r_quota:
#         quota_data = await r_quota.json()
#         dq = quota_data['data']['api_requests_daily']['user']
#         used, allowed = dq['used'], dq['allowed']
#         if used >= allowed:
#             reset_dt = next_reset_time()
#             now = datetime.now(timezone.utc)
#             sleep_secs = (reset_dt - now).total_seconds()
#             if sleep_secs > 0:
#                 print(f"[I] Daily quota reached. Sleeping {sleep_secs:.0f}s until {reset_dt.isoformat()}…")
#                 await asyncio.sleep(sleep_secs)

#     # 2) Fetch the file report
#     print(f"[P] Processing MD5: {md5} (folder: {folder})")
#     async with session.get(REPORT_URL_V3.format(id=md5)) as r_report:
#         if r_report.status == 200:
#             report = await r_report.json()
#             if 'error' in report:
#                 code = report['error'].get('code')
#                 msg = report['error'].get('message', '')
#                 if code == 'NotAvailableYet':
#                     print(f"[E] {md5} Not Available Yet")
#                 elif code == 'NotFoundError':
#                     print(f"[E] {md5} Not Found")
#                 else:
#                     print(f"[E] {md5} Error: {msg}")
#             else:
#                 await save_json_report(report, folder, md5)
#                 print(f"[S] Saved {md5}")
#         else:
#             print(f"[E] HTTP {r_report.status} for {md5}")

# async def read_and_process():
#     """Process each (folder, md5) pair from INPUT_LIST."""
#     # processed = await read_checkpoint()
#     processed = set()

#     async with aiohttp.ClientSession(headers={'x-apikey': API_KEY}) as session:
#         index = 1
#         for md5 in missed_hashes:
#             folder = hash2folder[md5]
#             print(f"Row {index}: MD5={md5}, folder={folder}")
#             index += 1

#             # if md5 in processed:
#             #     print(f"[I] Skipping {md5} (already processed)")
#             #     continue

#             try:
#                 await get_analysis(session, md5, folder)
#                 await write_checkpoint(md5)
#                 processed.add(md5)
#             except Exception as e:
#                 print(f"[E] Exception for {md5}: {e}")

#             # Throttle so we don’t exceed VT’s rate limit
#             await asyncio.sleep(4.32)

# async def main():
#     await read_and_process()

# if __name__ == '__main__':
#     asyncio.run(main())
