# import aiofiles
# import aiohttp
# import asyncio
# import csv
# import json
# import os
# from datetime import datetime, timedelta, timezone

# API_KEY = 'c031c25e22b76066f30d1331eedcfbd6fd9da095945526fb9c29cd48c2182a0'
# QUOTA_URL = 'https://www.virustotal.com/api/v3/users/{id}/overall_quotas'
# REPORT_URL = 'https://www.virustotal.com/api/v3/files/{id}'

# INPUT_FILE = '/shared/frankzha/data/hash/hashes.csv'
# CHECKPOINT_FILE = '/shared/frankzha/data/new_processed_frank_ai.txt'
# JSON_OUTPUT_DIR = '/shared/frankzha/data/new_json_reports_ai/'

# # When VT resets daily quotas at 00:01 UTC of the next day:
# _tomorrow = datetime.utcnow().date() + timedelta(days=1)
# RESET_DATETIME_UTC = datetime(_tomorrow.year, _tomorrow.month, _tomorrow.day,
#                               0, 1, tzinfo=timezone.utc)

# # How many coroutines to run at once
# MAX_CONCURRENT = 5


# async def read_checkpoint():
#     """Read already-processed MD5s into a set."""
#     if not os.path.exists(CHECKPOINT_FILE):
#         return set()
#     async with aiofiles.open(CHECKPOINT_FILE, 'r') as f:
#         lines = await f.readlines()
#     return {line.strip() for line in lines}


# async def write_checkpoint(md5: str):
#     """Append a new MD5 to the checkpoint file."""
#     async with aiofiles.open(CHECKPOINT_FILE, 'a') as f:
#         await f.write(md5 + '\n')


# async def save_json(report: dict, folder: str, md5: str):
#     """Persist the JSON report under JSON_OUTPUT_DIR/folder/md5.json."""
#     folder_path = os.path.join(JSON_OUTPUT_DIR, folder)
#     os.makedirs(folder_path, exist_ok=True)
#     path = os.path.join(folder_path, f"{md5}.json")
#     async with aiofiles.open(path, 'w') as f:
#         await f.write(json.dumps(report))


# async def fetch_quota(session: aiohttp.ClientSession):
#     """Get daily quota usage; returns (used, allowed)."""
#     url = QUOTA_URL.format(id=API_KEY)
#     async with session.get(url, headers={'x-apikey': API_KEY}) as resp:
#         data = await resp.json()
#         q = data['data']['api_requests_daily']['user']
#         return q['used'], q['allowed']


# async def fetch_report(session: aiohttp.ClientSession, md5: str):
#     """Fetch the VT report for a single hash; returns JSON or raises."""
#     url = REPORT_URL.format(id=md5)
#     async with session.get(url, headers={'x-apikey': API_KEY}) as resp:
#         if resp.status != 200:
#             raise RuntimeError(f"HTTP {resp.status}")
#         payload = await resp.json()
#         return payload


# async def process_row(semaphore: asyncio.Semaphore, session: aiohttp.ClientSession,
#                       folder: str, md5: str):
#     """Acquire a slot, check quota, fetch report, save, checkpoint."""
#     async with semaphore:
#         used, allowed = await fetch_quota(session)
#         if used >= allowed:
#             # Wait until reset
#             now = datetime.now(timezone.utc)
#             delay = (RESET_DATETIME_UTC - now).total_seconds()
#             if delay > 0:
#                 print(f"[!] Daily quota exhausted. Sleeping {delay/3600:.1f}h until reset.")
#                 await asyncio.sleep(delay)

#         print(f"[P] Fetching {md5}")
#         try:
#             report = await fetch_report(session, md5)
#         except Exception as e:
#             print(f"[E] Failed {md5}: {e}")
#             return

#         # Handle VT error codes inside the JSON
#         if 'error' in report:
#             code = report['error'].get('code', 'Unknown')
#             msg = report['error'].get('message', '')
#             print(f"[VT Error] {md5}: {code} {msg}")
#         else:
#             await save_json(report, folder, md5)
#             await write_checkpoint(md5)
#             print(f"[S] Saved {md5}")

#         # Rate‑limit courtesy pause
#         await asyncio.sleep(4.32)


# async def main():
#     processed = await read_checkpoint()

#     # Prepare a semaphore and a shared HTTP session
#     semaphore = asyncio.Semaphore(MAX_CONCURRENT)
#     connector = aiohttp.TCPConnector(limit_per_host=MAX_CONCURRENT)
#     async with aiohttp.ClientSession(connector=connector) as session:
#         tasks = []

#         # Read the CSV synchronously (fast) and schedule tasks
#         with open(INPUT_FILE, newline='') as f:
#             reader = csv.DictReader(f, fieldnames=['folder', 'filename', 'md5'])
#             for row in reader:
#                 md5 = row['md5']
#                 folder = row['folder']
#                 if md5 in processed:
#                     print(f"[.] Skip {md5}")
#                     continue
#                 tasks.append(
#                     process_row(semaphore, session, folder, md5)
#                 )

#         # Run all tasks, but don't blow the stack if there are thousands
#         for chunk in (tasks[i:i+MAX_CONCURRENT] for i in range(0, len(tasks), MAX_CONCURRENT)):
#             await asyncio.gather(*chunk)

# if __name__ == '__main__':
#     asyncio.run(main())

import asyncio
import aiohttp

API_KEY = 'c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0'  # ← your VT API key

async def fetch_report(session: aiohttp.ClientSession, md5: str):
    url = f"https://www.virustotal.com/api/v3/files/{md5}"
    headers = {'x-apikey': API_KEY}

    async with session.get(url, headers=headers) as resp:
        print(f"[{md5}] HTTP {resp.status}")
        try:
            body = await resp.json()
        except aiohttp.ContentTypeError:
            text = await resp.text()
            print(f"[{md5}] Non-JSON response:\n{text}")
            return

        # pretty‑print top‑level keys
        for k, v in body.items():
            snippet = '...' if isinstance(v, dict) else repr(v)
            print(f"  {k}: {snippet}")
        print()

async def main():
    # A handful of sample MD5s (valid VT scans or test files):
    sample_hashes = [
        "24f05da105834088c604c0a2bd4987f092ad3d743d86b7200d835a61e490bc28",
        "275a021bbfb6489e54d471899f3f408d",  # EICAR test file
        "44d88612fea8a8f36de82e1278abb02f",  # classic test string sample
        "d41d8cd98f00b204e9800998ecf8427e",  # empty file
        "e2fc714c4727ee9395f324cd2e7f331f",  # “hello” lowercase
        "5d41402abc4b2a76b9719d911017c592",  # “hello” (alternate)
    ]

    conn = aiohttp.TCPConnector(limit_per_host=5)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [fetch_report(session, md5) for md5 in sample_hashes]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
