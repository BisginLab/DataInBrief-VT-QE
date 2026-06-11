# import requests
# import csv
# import time
# from datetime import datetime, timedelta, timezone
# import os
# import json
# import pause
# from pprint import pprint

# """
# A few changes from submit_to_virustotal_report_ai:
# - Remove extract_stats_from_report() since the new responses
#   contain info about analysis statistics already
# - Remove output file path and initialize_output_csv()
#   (which was used to store analysis stats)
# - Exception handling is changed according to V2 -> V3 immigration

# curl --location 'https://www.virustotal.com/api/v3/files/24f05da105834088c604c0a2bd4987f092ad3d743d86b7200d835a61e490bc28' \
# --header 'x-apikey: c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0'
# """

# API_KEY = 'c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0'

# QUOTA_URL = 'https://www.virustotal.com/api/v3/users/{id}/overall_quotas'
# REPORT_URL_V3 = 'https://www.virustotal.com/api/v3/files/{id}'

# INPUT_FILE = '/shared/frankzha/data/hash/hashes.csv'
# CHECKPOINT_FILE = '/shared/frankzha/data/new_processed_frank_ai.txt'  # Writable file
# JSON_OUTPUT_DIR = '/shared/frankzha/data/new_json_reports_ai/'  # Base directory to save JSON reports

# _tmr = datetime.today() + timedelta(days=1)
# RESET_DATE = datetime(_tmr.year, _tmr.month, _tmr.day,
#                       hour=0, minute=1, tzinfo=timezone.utc)

# def read_csv(input_file):
#     processed_md5s = read_checkpoint()
#     with open(input_file, 'r') as file:
#         reader = csv.DictReader(file, fieldnames=['folder', 'filename', 'md5'])
#         index = 2
#         for row in reader:
#             print(row)
#             folder = row['folder']  # Read the folder name from the CSV
#             md5 = row['md5']
#             filename = row['filename']
#             print('Filename:', filename)
            
#             if md5 in processed_md5s:
#                 print(f"Skipping already processed MD5: {md5}")
#                 continue
            
#             print(f'Processing row {index}: {filename} with MD5 {md5}')
#             index += 1
            
#             try:
#                 get_analysis(md5, folder)
#                 write_checkpoint(md5)
#             except Exception as e:
#                 print(f"Error processing {md5}: {e}")
#                 continue  # Continue to the next row on error
            
#             time.sleep(4.32)  # Adjusting for the API rate limit


# def get_analysis(md5, folder):
#     try:
#         # [UPDATE] Added code to account for daily rate limit
#         r_quota = requests.get(QUOTA_URL.format(id = API_KEY), headers={'x-apikey': API_KEY})
#         daily_quota = r_quota.json()['data']['api_requests_daily']['user']
#         if daily_quota['used'] >= daily_quota['allowed']:
#             pause.until(RESET_DATE)
            
#         print('[P] Processing md5:', md5)
#         r_v3_report = requests.get(REPORT_URL_V3.format(id = md5), headers={'x-apikey': API_KEY})
#         if r_v3_report.status_code == 200:
#             report = r_v3_report.json()
#             if 'error' in report:
#                 if report['error']['code'] == 'NotAvailableYet':
#                     print(f'[E] Error with {md5}: Not Available')
#                 elif report['error']['code'] == 'NotFoundError':
#                     print(f'[E] Error with {md5}: Not Found')
#                 else:
#                     print(f'[E] Error with {md5}: {report['error']['message']}')
#             else:
#                 # Save the full JSON report
#                 save_json_report(report, folder, md5)
#                 print(f'[S] Success saving {md5}!')
#         else:
#             print(f"[E] Error fetching report for {md5}: HTTP {r_v3_report.status_code}")
#     except Exception as e:
#         # PROBLEM: The hash is saved to the checkpoint file even if the response is 504
#         print(f"[E] Error fetching report for {md5}: {repr(e)}")


# def save_json_report(report, folder, md5):
#     """Save the VirusTotal JSON report to a file, organized by folder."""
#     folder_path = os.path.join(JSON_OUTPUT_DIR, folder)  # Use folder from CSV

#     if not os.path.exists(folder_path):
#         os.makedirs(folder_path)  # Create subdirectory if it does not exist

#     json_file_path = os.path.join(folder_path, f"{md5}.json")
#     with open(json_file_path, 'w') as json_file:
#         json.dump(report, json_file)


# """Checkpoint handling"""
# def read_checkpoint():
#     if os.path.exists(CHECKPOINT_FILE):
#         with open(CHECKPOINT_FILE, 'r') as file:
#             processed_md5s = set(line.strip() for line in file)
#     else:
#         processed_md5s = set()
#     return processed_md5s


# def write_checkpoint(md5):
#     with open(CHECKPOINT_FILE, 'a') as file:
#         file.write(f"{md5}\n")

# def __main__():
#     read_csv(INPUT_FILE)

# __main__()
import aiohttp
import aiofiles
import asyncio
import csv
import os
import json
from datetime import datetime, timedelta, timezone

# Constants
API_KEY = 'c031c25e22b76066f30d1331e1edcfbd6fd9da095945526fb9c29cd48c2182a0'
QUOTA_URL = 'https://www.virustotal.com/api/v3/users/{id}/overall_quotas'
REPORT_URL_V3 = 'https://www.virustotal.com/api/v3/files/{id}'
INPUT_FILE = '/shared/frankzha/data/hash/hashes.csv'
CHECKPOINT_FILE = '/shared/frankzha/data/new_processed_frank_ai.txt'
JSON_OUTPUT_DIR = '/shared/frankzha/data/new_json_reports_ai/'


# Helper for daily reset
def next_reset_time() -> datetime:
    """Return the next occurrence of 00:01 UTC."""
    now = datetime.now(timezone.utc)
    tomorrow = now.date() + timedelta(days=1)
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day,
                    hour=0, minute=1, tzinfo=timezone.utc)


async def read_checkpoint() -> set:
    """Read processed MD5 hashes from checkpoint file."""
    processed = set()
    try:
        async with aiofiles.open(CHECKPOINT_FILE, mode='r') as f:
            async for line in f:
                processed.add(line.strip())
    except FileNotFoundError:
        pass
    return processed


async def write_checkpoint(md5: str):
    """Append a processed MD5 to the checkpoint file."""
    async with aiofiles.open(CHECKPOINT_FILE, mode='a') as f:
        await f.write(f"{md5}\n")


async def save_json_report(report: dict, folder: str, md5: str):
    """Save the JSON report under the given folder."""
    folder_path = os.path.join(JSON_OUTPUT_DIR, folder)
    os.makedirs(folder_path, exist_ok=True)
    file_path = os.path.join(folder_path, f"{md5}.json")
    async with aiofiles.open(file_path, mode='w') as f:
        await f.write(json.dumps(report))


async def get_analysis(session: aiohttp.ClientSession, md5: str, folder: str):
    """Fetch analysis report from VT and handle rate limits."""
    # Check daily quota
    async with session.get(QUOTA_URL.format(id=API_KEY)) as r_quota:
        quota_data = await r_quota.json()
        dq = quota_data['data']['api_requests_daily']['user']
        used, allowed = dq['used'], dq['allowed']
        if used >= allowed:
            reset_dt = next_reset_time()
            now = datetime.now(timezone.utc)
            sleep_secs = (reset_dt - now).total_seconds()
            if sleep_secs > 0:
                print(f"[I] Daily quota reached. Sleeping {sleep_secs:.0f}s until {reset_dt.isoformat()}…")
                await asyncio.sleep(sleep_secs)

    # Fetch report
    print(f"[P] Processing MD5: {md5}")
    async with session.get(REPORT_URL_V3.format(id=md5)) as r_report:
        if r_report.status == 200:
            report = await r_report.json()
            if 'error' in report:
                code = report['error'].get('code')
                msg = report['error'].get('message', '')
                if code == 'NotAvailableYet':
                    print(f"[E] {md5} Not Available Yet")
                elif code == 'NotFoundError':
                    print(f"[E] {md5} Not Found")
                else:
                    print(f"[E] {md5} Error: {msg}")
            else:
                await save_json_report(report, folder, md5)
                print(f"[S] Saved {md5}")
        else:
            print(f"[E] HTTP {r_report.status} for {md5}")


async def read_and_process():
    """Read CSV and process each unprocessed hash."""
    processed = await read_checkpoint()

    async with aiofiles.open(INPUT_FILE, mode='r') as f:
        lines = await f.read()
    reader = csv.DictReader(lines.splitlines(), fieldnames=['folder', 'filename', 'md5'])

    async with aiohttp.ClientSession(headers={'x-apikey': API_KEY}) as session:
        index = 2
        for row in reader:
            folder = row['folder']
            md5 = row['md5']
            filename = row['filename']

            print(f"Row {index}: {filename} ({md5})")
            index += 1
            if md5 in processed:
                print(f"[I] Skipping {md5}")
                continue

            try:
                await get_analysis(session, md5, folder)
                await write_checkpoint(md5)
                processed.add(md5)  # prevent reprocessing within same run
            except Exception as e:
                print(f"[E] Exception for {md5}: {e}")

            await asyncio.sleep(4.32)


async def main():
    await read_and_process()


if __name__ == '__main__':
    asyncio.run(main())
