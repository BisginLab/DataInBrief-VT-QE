#!/usr/bin/env python
import sys
from time import perf_counter
from apkid.apkid import Options, Scanner


apk_file = '/mnt/data/Android-Data/APKs/eapks1/com.gamemaniac.DXBall.brick.ball.rolling.fun.apk'

# Initialize scan options.
# Here we disable JSON output so we can process and print the results directly.
options = Options(timeout=40, verbose=True, json=False)

# Create a Scanner object using the rules provided by the Options instance.
scanner = Scanner(options.rules_manager.load(), options)
print(options.rules_manager.rules)

# Scan the APK file. The scan_file method returns a dictionary where
# keys are file paths (or nested zip entries) and values are lists of yara.Match objects.
results = scanner.scan_file(apk_file)

# Check if any matches were found and print details.
start = perf_counter()
if results:
    print("Scan Results:")
    for file_path, matches in results.items():
        print(f"\nFile: {file_path}")
        if matches is not None:
            for match in matches:
                print(f"  Rule   : {match.rule}")
                print(f"  Tags   : {match.tags}")
                print(f"  Meta   : {match.meta}")
                print("-" * 40)
else:
    print("No suspicious features detected.")
end = perf_counter()
print(end - start)