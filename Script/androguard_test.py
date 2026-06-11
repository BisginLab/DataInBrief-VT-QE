import os
import json
import pandas as pd
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

def extract_advanced_features(apk_path):
    """Extracts advanced APK features (permissions, API calls, strings, signatures, etc.)"""

    features = {"file_name": os.path.basename(apk_path)}
    
    try:
        apk = APK(apk_path)
        dex = DalvikVMFormat(apk.get_dex())

        # Manifest Features
        features["package_name"] = apk.get_package()
        features["version"] = apk.get_androidversion_name()
        features["permissions"] = apk.get_permissions()
        features["activities"] = apk.get_activities()
        features["services"] = apk.get_services()
        features["receivers"] = apk.get_receivers()
        features["exported_components"] = len([c for c in apk.get_receivers() if "exported" in c])

        # Code Analysis
        features["num_methods"] = len(dex.get_methods())
        features["num_classes"] = len(dex.get_classes())
        features["num_strings"] = len(dex.get_strings())

        # API Calls
        api_calls = set()
        # for method in dex.get_methods():
        #     code = method.get_code()
        #     if code:
        #         dcode = code.get_bc()  # Retrieve the DCode object
        #         for ins in dcode.get_instructions():
        #             print(ins.get_name(), ins.get_output())

        features["suspicious_api_calls"] = list(api_calls)

        # Hardcoded Strings (URLs, IPs)
        features["hardcoded_urls"] = [str(s) for s in dex.get_strings() if s.startswith("http")]

        # Certificate Analysis
        features["certificate_name"] = apk.get_signature_name()

    except Exception as e:
        print(f"Error processing {apk_path}: {e}")

    return features

def analyze_apk(apk_path, output_file="apk_advanced_features.json"):
    """Analyzes an APK file and saves extracted features to a JSON file."""
    features = extract_advanced_features(apk_path)

    with open(output_file, "w") as f:
        json.dump(features, f, indent=4)

    print(f"Advanced analysis saved to {output_file}")

if __name__ == "__main__":
    apk_file = "/mnt/data/Android-Data/APKs/eapks1/com.gamemaniac.DXBall.brick.ball.rolling.fun.apk"
    analyze_apk(apk_file)
