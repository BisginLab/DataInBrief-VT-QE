# """
# This script randomly samples 50 APK files from the source folder
# and move them into a new folder
# """
# import os
# import shutil
# import random

# SOURCE_FOLDER = "/mnt/data/Android-Data/APKs/eapks1"
# DEST_FOLDER = "/shared/frankzha/data/reports"

# # Ensure the destination directory exists; if not, create it.
# if not os.path.exists(DEST_FOLDER):
#     os.makedirs(DEST_FOLDER)
#     print(f"Created destination directory: {DEST_FOLDER}")

# # List all files in the source directory and filter for files ending with .apk (case-insensitive).
# # os.listdir returns file names, so we join them with src_dir to check if they're actual files.
# apk_files = [
#     file_name for file_name in os.listdir(SOURCE_FOLDER)
#     if file_name.lower().endswith('.apk') and os.path.isfile(os.path.join(SOURCE_FOLDER, file_name))
# ]

# if len(apk_files) < 50:
#     raise ValueError(f"Not enough APK files in the source directory ({len(apk_files)} found). Need at least 50.")

# # Randomly sample 50 APK files from the list
# sample_files = random.sample(apk_files, 50)

# # Move each sampled APK file from the source to the destination directory
# for file_name in sample_files:
#     # Build full file paths for source and destination.
#     source_file = os.path.join(SOURCE_FOLDER, file_name)
#     dest_file = os.path.join(DEST_FOLDER, file_name)
    
#     # Use shutil.move to move the file.
#     shutil.move(source_file, dest_file)
#     print(f"Moved '{source_file}' to '{dest_file}'")


import os
import shutil
import random

SOURCE_FOLDER = "/mnt/data/Android-Data/APKs/eapks1"
DEST_FOLDER = "/shared/frankzha/data/reports"

# Ensure the destination directory exists; if not, create it.
if not os.path.exists(DEST_FOLDER):
    os.makedirs(DEST_FOLDER)
    print(f"Created destination directory: {DEST_FOLDER}")

apk_files = [
    file_name for file_name in os.listdir(SOURCE_FOLDER)
    if file_name.lower().endswith('.apk') and os.path.isfile(os.path.join(SOURCE_FOLDER, file_name))
]

random.seed(42)     # Set seeds so it samples the same files every time
# Randomly sample 100 APK files from the list
sample_files = random.sample(apk_files, 100)
print(sample_files)


# f = '/mnt/data/Android-Data/APKs/eapks1/com.gamemaniac.DXBall.brick.ball.rolling.fun.apk'
# with open(f) as file:
#     print(file.read())
    
#!/usr/bin/env python3

import os
import glob

# Import the core API interface from Quark-engine.
# (This is the integration API as documented at the integration page.)
from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject

# Set these paths as appropriate for your environment.
apk_folder = SOURCE_FOLDER        # Folder containing your APK files.
output_folder = "/shared/frankzha/scripts/quark_engine_test/reports"    # Folder where reports should be saved.

RULE_DIR = '/home/umflint.edu/frankzha/.quark-engine/quark-rules/rules'


"""
# Process each APK file.
for apk in apk_files:
    apk_basename = os.path.basename(apk)
    print(f"Analyzing {apk_basename} ...")
    
    source_file = os.path.join(SOURCE_FOLDER, apk)
    
    # Define an output file path for the summary report (e.g., a .txt file)
    output_file = os.path.join(output_folder, f"{apk_basename}_summary.json")
    
    # Analyze the APK and get the summary report.
    report = analyze_apk(source_file, output_file)
    
    # Print the summary report to the console.
    print(report)
    print("-" * 80)
    break


for rule_file in os.listdir(RULE_DIR):
    rule = RuleObject(ruleJson=rule_file)
    engine = Quark(apk_path)
    
        
    # Obtain the summary report; this should match the output of "-s" in CLI.
    report = engine.get_json_report()
    # show_summary_report(self, rule_obj)
    #get_json_report(self)
    
    # Optionally, save the report to an output file.
    # if output_path:
    #     with open(output_path, "w") as f:
    #         f.write(report)
    
    # self.quark_analysis.summary_report_table
    engine.show_summary_report(rule_obj=rule)
    
"""


from time import perf_counter
from pprint import pprint

pattern = r"confidence':\s*'([1-9])'"


for apk_file in apk_files:    
    source_file = os.path.join(SOURCE_FOLDER, apk_file)
    # source_file = '/mnt/data/Android-Data/APKs/eapks1/com.gamemaniac.DXBall.brick.ball.rolling.fun.apk'
    print(f"Analyzing {source_file} ...")
    # Define an output file path for the summary report (e.g., a .txt file)
    output_file = os.path.join(output_folder, f"{source_file}_summary.json")
        
    # Print the summary report to the console.
    
    engine = Quark(source_file)
    
    start = perf_counter()
    for rule_file in os.listdir(RULE_DIR):
        rule = RuleObject(ruleJson=os.path.join(RULE_DIR, rule_file))
        engine.run(rule)
        engine.show_summary_report(rule)
        
    end = perf_counter()
    print(f'{end - start} seconds elpased!')
    
    print(engine.quark_analysis.summary_report_table)
    pprint(engine.get_json_report())

    
    break
    

