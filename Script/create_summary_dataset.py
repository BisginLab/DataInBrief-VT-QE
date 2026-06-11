import csv
import os
import multiprocessing as mp
from datetime import datetime
from pprint import pprint

from tqdm import tqdm

from utility import *

SUMMARY_DATASET_FILE = '/shared/frankzha/data/datasets/summary_dataset.csv'
QK_RESCANNED_DIR = '/shared/frankzha/data/log_file/rescanned_qk_files/'

FEATURES = ('md5',
            'malicious_count',
            'undetected_count',
            'certificate_life_days',
            'file_duration_days',
            'times_submitted',
            'threat_level',
            'aggregated_risk_score',
            'weighted_conf_sum',
            'permission_n',
            'avg_weight')

# Compute files common to both VirusTotal (v3) and Quark-engine
vt_ai_stem2path = {p.stem: p for p in get_all_vt_ai_files()}
qk_stem2path = {p.stem: p for p in get_qk_files()}

vt_qk_files = {
    (vt_ai_stem2path[s], qk_stem2path[s])
    for s in vt_ai_stem2path.keys() & qk_stem2path.keys()
}

print(f'There are {len(vt_ai_stem2path)} VirusTotal (v3) responses.')
print(f'There are {len(qk_stem2path)} Quark-engine responses.')
print(f'There are {len(vt_qk_files)} common files.')


def parse_cert_date(s: str) -> datetime:
    for fmt in ('%Y-%m-%d %H:%M:%S', '%I:%M %p %m/%d/%Y'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unknown certificate date format: {s!r}")

# def save_vt_qk_file(args):
#     try:
#         (vt_file, qk_file), i = args
#         vt_res = load_json_path_repair(vt_file)
#         if vt_res is None:
#             raise JSONParseError(f'VirusTotal file {vt_file.name} fails to load', 'vt_json', vt_file)

#         subpath = "/".join(qk_file.parts[-2:])  # subfolder name + file name
#         rescanned_qk_file = Path(QK_RESCANNED_DIR) / subpath  # 1581 QK original files cannot be parsed, so we rescanned them
#         print(f'{rescanned_qk_file=}')
#         if os.path.exists(rescanned_qk_file):
#             qk_res = load_json_path_repair(rescanned_qk_file)
#         else:
#             qk_res = load_json_path_repair(qk_file)
#         if qk_res is None:
#             raise JSONParseError(f'Quark-engine file {qk_file.name} fails to load', 'qk_json', qk_file)
        
        
#         # Extract the 5 features from VirusTotal
#         with error_tracker('attributes', vt_file, i):
#             attrs = vt_res['data']['attributes']
            
#         with error_tracker('last_analysis_stats', vt_file, i):
#             stats = attrs['last_analysis_stats']
#             # 1: Malicious detection count
#             malicious_count = stats['malicious']
#             # 2: Undetected detection count
#             undetected_count = stats['undetected']
            
#         with error_tracker('certificate', vt_file, i):
#             # 3: Certificate life duration (in days)
#             cert = attrs['androguard']['certificate']
            
#         with error_tracker('validfrom', vt_file, i):
#             valid_from = parse_cert_date(cert['validfrom'])
        
#         with error_tracker('validto', vt_file, i):
#             valid_to = parse_cert_date(cert['validto'])
#             certificate_life_days = (valid_to - valid_from).days

#         # 4: Duration of file existence on VirusTotal
#         with error_tracker('first_submission_date', vt_file, i):
#             first_ts = attrs['first_submission_date']
            
#         with error_tracker('last_analysis_date', vt_file, i):
#             last_ts = attrs['last_analysis_date']
#             first_dt = datetime.fromtimestamp(first_ts)
#             last_dt = datetime.fromtimestamp(last_ts)
#             file_duration_days = (last_dt - first_dt).days
            
#         # 5: Times Submitted
#         with error_tracker('times_submitted', vt_file, i):
#             times_submitted = attrs['times_submitted']
            
#         # Extract the 5 features from Quark-engine
#         # 0: Hash value
#         with error_tracker('md5', qk_file, i):
#             md5 = qk_res['md5']
            
#         # 6: Threat level
#         with error_tracker('threat_level', qk_file, i):
#             threat_level = qk_res['threat_level']
            
#         # 7: Aggregated risk score
#         with error_tracker('total_score', qk_file, i):
#             aggregated_risk_score = qk_res['total_score']
            
#         # 8: Weighted confidence sum
#         weighted_conf_sum = 0.0
#         weights = []
        
#         # 9: Permission count
#         permission_n = 0
        
#         for crime in qk_res['crimes']:
#             with error_tracker('weight', qk_file, i):
#                 weight = crime['weight']
#                 weights.append(weight)
#                 # Parse confidence (e.g., "40%" -> 0.4)
#                 conf = float(crime['confidence'].removesuffix('%')) / 100
#                 weighted_conf_sum += weight * conf
#                 # Count crimes requiring permissions
#                 if crime.get('permissions'):
#                     permission_n += 1

#         # 10: Average weight
#         with error_tracker('weights', qk_file, i):
#             # TypeError: unsupported operand type(s) for +: 'float' and 'str'
#             avg_weight = sum(weights) / len(weights) if weights else 0.0
                    
#         return ('SUCCESS', [
#             md5,
#             # VirusTotal features
#             malicious_count, undetected_count, certificate_life_days,
#             file_duration_days, times_submitted,
#             # Quark-engine features
#             threat_level, aggregated_risk_score, weighted_conf_sum,
#             permission_n, avg_weight
#         ])
#     except JSONParseError as je:
#         return ('JSON_ERROR', je.err_feature)
#     except SkipFileError as se:
#         print(type(se).__name__, se)
#         return ('SKIP_ERROR', se.err_feature)
    
def save_vt_qk_file(args):
    (vt_file, qk_file), _ = args
    vt_res = load_json_path_repair(vt_file)
    try:
        if vt_res is None:
            raise JSONParseError(f'VirusTotal file {vt_file.name} fails to load', 'vt_json', vt_file)

        subpath = "/".join(qk_file.parts[-2:])  # subfolder name + file name
        rescanned_qk_file = Path(QK_RESCANNED_DIR) / subpath
        if os.path.exists(rescanned_qk_file):
            qk_res = load_json_path_repair(rescanned_qk_file)
        else:
            qk_res = load_json_path_repair(qk_file)
        if qk_res is None:
            raise JSONParseError(f'Quark-engine file {qk_file.name} fails to load', 'qk_json', qk_file)

        # Extract VirusTotal features with defaults for missing values
        attrs = vt_res.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', -1)
        undetected_count = stats.get('undetected', -1)

        cert = attrs.get('androguard', {}).get('certificate', {})
        valid_from_str = cert.get('validfrom')
        valid_to_str = cert.get('validto')
        if valid_from_str and valid_to_str:
            valid_from = parse_cert_date(valid_from_str)
            valid_to = parse_cert_date(valid_to_str)
            certificate_life_days = (valid_to - valid_from).days
        else:
            certificate_life_days = -1

        first_ts = attrs.get('first_submission_date')
        last_ts = attrs.get('last_analysis_date')
        if first_ts is not None and last_ts is not None:
            first_dt = datetime.fromtimestamp(first_ts)
            last_dt = datetime.fromtimestamp(last_ts)
            file_duration_days = (last_dt - first_dt).days
        else:
            file_duration_days = -1

        times_submitted = attrs.get('times_submitted', -1)

        # Extract Quark-engine features
        md5 = qk_res.get('md5')  # will be None if missing
        threat_level = qk_res.get('threat_level', -1)
        aggregated_risk_score = qk_res.get('total_score', -1)

        weighted_conf_sum = 0.0
        weights = []
        permission_n = 0

        for crime in qk_res.get('crimes', []):
            weight = crime.get('weight', -1)
            weights.append(weight)
            conf_str = crime.get('confidence', '0%')
            try:
                conf = float(conf_str.rstrip('%')) / 100
            except ValueError:
                conf = 0.0
            weighted_conf_sum += weight * conf
            if crime.get('permissions'):
                permission_n += 1

        avg_weight = sum(weights) / len(weights) if weights else -1
        return ('SUCCESS', [
            md5,
            malicious_count, undetected_count, certificate_life_days,
            file_duration_days, times_submitted,
            threat_level, aggregated_risk_score, weighted_conf_sum,
            permission_n, avg_weight
        ])
    except JSONParseError as je:
        return ('JSON_ERROR', je.err_feature)
    
def create_csv():
    err_cnt: dict[str, int] = dict.fromkeys(
        ('vt_json', 'qk_json', 'attributes', 'last_analysis_stats',
         'certificate', 'validfrom', 'validto',
         'first_submission_date', 'last_analysis_date',
         'times_submitted', 'md5', 'threat_level', 'total_score',
         'weight', 'confidence', 'weights'),
        0
    )
    correct_file_n = 0
    with (mp.Pool(processes=16) as pool,
          open(SUMMARY_DATASET_FILE, mode='w', newline='') as csvfile):
        writer = csv.writer(csvfile)
        # Write the header row, including 1 ID + 10 features:
        writer.writerow(
            ['md5',
             'malicious_count',
             'undetected_count',
             'certificate_life_days',
             'file_duration_days',
             'times_submitted',
             'threat_level',
             'aggregated_risk_score',
             'weighted_conf_sum',
             'permission_n',
             'avg_weight']
        )
        # Write the body
        tasks = [(file_pair, i) for i, file_pair in enumerate(vt_qk_files, start=1)]
        results = pool.imap_unordered(save_vt_qk_file, tasks)

        for row in tqdm(results, total=len(tasks), desc="Processing files"):
            if row[0] == 'SUCCESS':
                correct_file_n += 1
                features = row[1]
                writer.writerow(features)
                
        print(f'All {len(tasks)} rows have been processed!')
        # print(f"Created CSV file with {correct_file_n} rows.")
        print(f'Error rate: {(1 - correct_file_n/len(tasks)):.4%}')
        # pprint(err_cnt)


if __name__ == '__main__':
    create_csv()
    

# 53 No last_analysis_stats!
# /shared/frankzha/data/datasets/oddity/fst_time_benign/252245a025f166632e65e23ee3342586.json