"""
API response format:
{
  "md5": "aa4ebe673b66abb25b3e0f97c188f7b0",
  "permalink": "https://www.virustotal.com/gui/file/9b62a38bfc80d95d9774a280ca53e64d841af14966c496e9b1ec8fed0b3def9d/detection/f-9b62a38bfc80d95d9774a280ca53e64d841af14966c496e9b1ec8fed0b3def9d-1553338192",
  "positives": 0,
  "resource": "aa4ebe673b66abb25b3e0f97c188f7b0",
  "response_code": 1,
  "scan_date": "2019-03-23 10:49:52",
  "scan_id": "9b62a38bfc80d95d9774a280ca53e64d841af14966c496e9b1ec8fed0b3def9d-1553338192",
  "scans": {
    "ALYac": {
      "detected": false,
      "result": null,
      "update": "20190323",
      "version": "1.1.1.5"
    },
    "Ad-Aware": {
      "detected": false,
      "result": null,
      "update": "20190323",
      "version": "3.0.5.370"
    },
    ...,
    "Zoner": {
      "detected": false,
      "result": null,
      "update": "20190323",
      "version": "1.0"
    }
  },
  "sha1": "77c9ff284def66f7084906f31c8eb386a76f6fbf",
  "sha256": "9b62a38bfc80d95d9774a280ca53e64d841af14966c496e9b1ec8fed0b3def9d",
  "total": 52,
  "verbose_msg": "Scan finished, information embedded"
}
{
  "stats": {
    "harmless": 0,
    "type-unsupported": 0,
    "suspicious": 0,
    "confirmed-timeout": 0,
    "timeout": 0,
    "failure": 0,
    "malicious": 0,
    "undetected": 52
  }
}
"""



import os

# Define the directory containing the JSON files and the output file
json_directory = '/shared/frankzha/data/quark_engine_results/eapks10'
output_file = '/shared/frankzha/data/quark_engine_results/quark_checkpoint.txt'

# Open the output file for writing
with open(output_file, 'w') as outfile:
    # Iterate over each file in the specified directory
    for filename in os.listdir(json_directory):
        # Check if the file ends with .json
        if filename.endswith('.json'):
            # Extract the MD5 part by removing the '.json' extension
            md5_hash = filename[:-5]
            # Write the MD5 to the output file, each on a new line
            outfile.write(md5_hash + "\n")
