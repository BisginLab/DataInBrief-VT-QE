import requests
import csv
import time
from datetime import datetime, timedelta, timezone
import os
import json
import pause
from pprint import pprint

API_KEY = 'f8c4555f34f9900ea49bb4648073458467ecce535377870926b38b694f6bc7c6'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
md5 = 'f415e5d4d04bef0c5b5f34b189bfda50'

params = {'apikey': API_KEY, 'resource': md5}    
r_report = requests.get(REPORT_URL, params=params)
print(r_report.json())

# if r_report.status_code == 200:
#     report = r_report.json()
#     # Check if the response has a valid scan report
#     if report['response_code'] == 1:
#         # Extract the last analysis statistics
#         stats = extract_stats_from_report(report)
#         print('stats:', stats)
#         write_to_file(stats, filename, md5)
        
#         # Save the full JSON report and stats
#         save_json_report(report, stats, folder, md5)
#     else:
#         print(f"File {md5} not found on VirusTotal.")
# else:
#     print('Error')
#     print(f"Error fetching report for {md5}: HTTP {r_report.status_code}")
# except Exception as e:
# # PROBLEM: The hash is saved to the checkpoint file even if the response is 504
# print()
# print(f"Error fetching report for {md5}: {e}")

