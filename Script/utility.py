from pathlib import Path
from typing import Iterator
from contextlib import contextmanager
import pickle
import os
import re
import json
import csv
import traceback

import json_repair as jr  # fix malformed JSON file
import msgspec  # efficient library for JSON parsing
import openai

APK_DIR = '/mnt/data/Android-Data/APKs'
HASH_FILE = '/shared/frankzha/data/hash/hashes.csv'

QUARK_FST_SCAN_DIR = "/shared/frankzha/data/quark_engine_results/qk_fst_scan"
QUARK_RESCAN_DIR  = "/shared/frankzha/data/quark_engine_results/qk_rescan"

VT_AI_RELIABLE_DIR = "/shared/frankzha/data/new_json_reports_ai/"
VT_AI_FST_TIME_BENIGN_DIR = '/shared/frankzha/data/datasets/oddity/fst_time_benign'
VT_OG_DIR = "/shared/frankzha/data/_past_json_reports/json_reports/"

PAPER_FILE = '/shared/evanroot/manifests_dir/paper_replication/corrected_permacts.csv'
# File that encodes the mapping between hashes to package names
PKG_MAP_FILE = '/shared/henrysfiles/Android-Data/Hash Calculation/md5_hashes.csv'
PAPER_STATUS_INDEX = 34   # index of the status (whether the app is removed or not)

_PICKLE_OBJ_DIR = '/shared/frankzha/data/_pickle_obj'

_openai_api_key = ('sk-proj-RX9BCsg16JAzHUzTu2ah5hxVY14L3cDJGqe9I5q2N8LOnxH'
                   'HhBf7eL8lMuYrcY7QYloWwv73OOT3BlbkFJ34y2jpotTOd5968dwREb'
                   'rtdPd_hGy8KX4RYJIJOo9un4esUgbOAvWeDs1OxOxZoLGJXELh9_MA')

client = openai.OpenAI(api_key=_openai_api_key)


def path2names(paths: set[Path] | list[Path]) -> set[str]:
    """Convert file paths to filenames 
    """
    return {path.name for path in paths}


def get_qk_files() -> set[Path]:
    """Return a set of 772733 file paths, each corresponding to a Quark-Engine response.
        
    [note] Use path2names(get_qk_files()) to get a set of quark filenames. 
    """
    return (set(Path(QUARK_FST_SCAN_DIR).rglob('*.json')) |
            set(Path(QUARK_RESCAN_DIR).rglob('*.json')))
    
        
def get_all_vt_ai_files() -> set[Path]:
    """Return a set of 803335 file paths, each corresponding to a VirusTotal V3 response.
    All 
    [note] Use path2names(get_quark_files()) to get a set of quark filenames. 
    """
    return (set(Path(VT_AI_RELIABLE_DIR).rglob('*.json')) |
            set(Path(VT_AI_FST_TIME_BENIGN_DIR).rglob('*.json')))
            

def get_reliable_vt_ai_files() -> set[Path]:
    """Return a set of  file paths, each corresponding to a VirusTotal V3 response.
    Only malicious files and benign files with times_submitted > 1 are kept.
    
    [note] Use path2names(get_quark_files()) to get a set of quark filenames. 
    """
    return set(Path(VT_AI_RELIABLE_DIR).rglob('*.json'))


def get_vt_og_files() -> set[Path]:
    """Return a set of 803335 file paths, each corresponding to a VirusTotal V2 response.
    
    [note] Use path2names(get_quark_files()) to get a set of quark filenames. 
    """
    return set(Path(VT_OG_DIR).rglob('*.json'))

    
# JSON_DICT_DECODER = msgspec.json.Decoder(dict)
# JSON_ARR_DECODER = msgspec.json.Decoder(list)

def load_json_path_repair(path: Path,) -> dict | None:
    """
    """
    raw = path.read_bytes().decode("utf-8-sig", errors="replace")
    try:
        return msgspec.json.decode(raw)
    except msgspec.DecodeError:
        cleaned = jr.repair_json(raw, skip_json_loads=True).strip()
        try:
            res = msgspec.json.decode(cleaned)
            if isinstance(res, list):
                return res[0]
            return res
        except msgspec.DecodeError as e:
            # print(f'[{i}] {type(e).__name__}: {e} (see below)')
            # print(f'Error occurs at: {path.absolute()}\n')
            return None

"""
@contextmanager
def error_tracker(
    error_cnt: dict[str, int],
    error_type: str,
    error_file: Path,
    i: int
):
    '''Context manager for exception handling. If an exception is raised, it uses h
    '''  
    try:
        yield
        
    except KeyError as ke:
        # Suppress the error because it indicates missing keys (cannot be fixed)
        # print(f'[{i}] {type(e).__name__}: {ke} (see below)')
        # traceback.print_exc()
        # print(f'Error occurs at: {error_file.absolute()}\n')
        raise SkipFileError
    
    except Exception as e:
        # Let the error propogate because it indicates other preventable errors
        # print(f'[{i}] {e} (see below)')
        # traceback.print_exc()
        # print(f'Error occurs at: {error_file.absolute()}\n')
        # error_cnt[error_type] += 1
        raise SkipFileError
"""

class FeatureError(Exception):
    def __init__(self, msg: str, err_feature: str, err_path: Path):
        super().__init__(msg)
        self.err_feature = err_feature
        self.err_path = err_path

class SkipFileError(FeatureError):
    pass

class JSONParseError(FeatureError):
    pass
        
@contextmanager
def error_tracker(err_feature: str, err_file: Path, i: int):
    try:
        yield
    except KeyError as e:
        # print(f'[{i}] {e} (see below)')
        # traceback.print_exc()
        # print(f'Error occurs at: {error_file.absolute()}\n')
        msg = f"Skipping due to {type(e).__name__}: {e} (feature: `{err_feature}`)"
        raise SkipFileError(msg, err_feature, err_file) from e
    except Exception as e:
        # [TODO] We should handle this differently than KeyError (which cannot be fixed)!
        msg = f"Skipping due to {type(e).__name__}: {e} (feature: `{err_feature}`)"
        raise SkipFileError(msg, err_feature, err_file) from e


# [Div] [Div] [Div]

def load_pkg2hash() -> dict[str, str]:
    pickle_path = os.path.join(_PICKLE_OBJ_DIR, 'pkg2hash.pkl')
    if os.path.exists(pickle_path):
        with open(pickle_path, 'rb') as file:
            pkg2hash = pickle.load(file)
        return pkg2hash
    
    pkg2hash = {}  # Stores a mapping between all the package names to their hashes, folder, etc.
    with open(PKG_MAP_FILE) as map_file:
        map_reader = csv.reader(map_file)
        fieldnames = next(map_reader)
        for row in map_reader:
            pkg_name = row[1]
            hash_value = row[2]
            if pkg_name[-4:] == '.apk':
                pkg_name = pkg_name[:-4]
            pkg2hash[pkg_name] = hash_value
    
    with open(pickle_path, 'wb') as file:
        pickle.dump(pkg2hash, file)
        
    return pkg2hash


def load_hash2malicious() -> dict[str, int]:
    pickle_path = os.path.join(_PICKLE_OBJ_DIR, 'hash2malicious.pkl')
    if os.path.exists(pickle_path):
    # if 0:
        with open(pickle_path, 'rb') as f:
            hash2malicious = pickle.load(f)
        return hash2malicious

    hash2malicious = {}
    for f in get_all_vt_ai_files():
        vt_report = load_json_path_repair(f)
        if vt_report is None:
            continue
        
        attr = vt_report.get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})
        malicious = stats.get('malicious')
        filename = os.path.basename(f.name)
        hash2malicious[filename[:-5]] = malicious
    
    with open(pickle_path, 'wb') as file:
        pickle.dump(hash2malicious, file)
        
    return hash2malicious
            
            
def load_hash2risk() -> dict[str, str]:
    pickle_path = os.path.join(_PICKLE_OBJ_DIR, 'hash2risk.pkl')
    if os.path.exists(pickle_path):
    # if 0:
        with open(pickle_path, 'rb') as f:
            hash2risk = pickle.load(f)
        return hash2risk
    
    hash2risk = {}
    for f in get_qk_files():
        threat_level_match = re.search(r'"threat_level":\s*"([^"]+)"', f.read_text())
        if threat_level_match:
            filename = os.path.basename(f.name)
            threat_level = threat_level_match.group(1)
            hash2risk[filename[:-5]] = threat_level.split()[0].lower()
                
    with open(pickle_path, 'wb') as file:
        pickle.dump(hash2risk, file)
        
    return hash2risk


def load_apk_files() -> list[str]:
    pickle_path = os.path.join(_PICKLE_OBJ_DIR, 'apk_files.pkl')
    if os.path.exists(pickle_path):
        with open(pickle_path, 'rb') as f:
            apk_files = pickle.load(f)
        return apk_files
    
    apk_files = []
    for subfolder in Path(APK_DIR).glob('eapks*'):
        if '_' not in subfolder.name:
            for f_path in subfolder.glob('*.apk'):
                apk_files.append(os.path.join(subfolder.name, f_path.name))
                
    with open(pickle_path, 'wb') as f:
        pickle.dump(apk_files, f)
    
    return apk_files


def load_hash2folder() -> dict[str, str]:
    pickle_path = os.path.join(_PICKLE_OBJ_DIR, 'hash2folder.pkl')
    if os.path.exists(pickle_path):
        with open(pickle_path, 'rb') as f:
            hash2folder = pickle.load(f)
        return hash2folder
    
    hash2folder = {}
    with open(HASH_FILE, newline='') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            # row[0] is the folder, row[2] is the MD5
            folder, _, md5 = row
            hash2folder[md5] = folder
    
    with open(pickle_path, 'wb') as f:
        pickle.dump(hash2folder, f)
    
    return hash2folder


'''
def load_json_path_llm(
    path: Path,
    counter: Iterator[int] | None = None
) -> dict:
    """
    If the JSON decoder cannot decode the response, trigger an LLM (GPT 4o-mini) response
                 to correct the JSON response.
    """
    text = re.sub(r"\\s+", '', path.read_bytes().decode('utf-8-sig', errors='replace'))
    try:
        return JSON_DECODER.decode(text)
    except msgspec.DecodeError:
        if counter is not None:
            next(counter)
        corrected_text = client.chat.completions.create(
            model='o4-mini',
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a JSON linter/fixer. "
                        "Given a malformed JSON document, "
                        "make the minimal edits needed so that the result is valid JSON. "
                        "Do NOT add or remove any data beyond what's necessary to fix syntax. "
                        "Only output the corrected JSON, nothing else. No spaces, tabs, or newlines."
                    )
                },
                {
                    "role": "user",
                    "content": f"```json\n{text}\n```"
                }
            ],
            max_completion_tokens=7000
        ).choices[0].message.content.strip()
        return JSON_DECODER.decode(corrected_text)
'''
"""
path = '/shared/frankzha/data/log_file/rescanned_qk_files/eapks19/68cef9725154d360dfe5e469d2ecccf1.json'


rescan_dir = '/shared/frankzha/data/log_file/rescanned_qk_files'
n = 0

for p in Path(rescan_dir).rglob('*.json'):
    raw = Path(p).read_bytes().decode("utf-8-sig", errors="replace")
    try:
        msgspec.json.decode(raw)
    except msgspec.DecodeError:
        print(f'Wrong at {n}')
        
    n += 1
    
print(n)


# /shared/frankzha/data/quark_engine_results/qk_fst_scan/eapks10/023d49fce36eb57c8115bedb81e290c4.json
p1 = Path('/shared/frankzha/data/quark_engine_results/qk_fst_scan/eapks10/023d49fce36eb57c8115bedb81e290c4.json')
p2 = Path('/shared/frankzha/data/log_file/rescanned_qk_files/eapks10/023d49fce36eb57c8115bedb81e290c4.json')
print(p1.read_bytes() == p2.read_bytes())
print(p2.read_bytes()[:20])

with open('/shared/frankzha/data/log_file/malformed_qk_files.txt') as f:
    for p in map(Path, f):
        raw = p.read_bytes().decode("utf-8-sig", errors="replace")
        print()
        msgspec.json.decode(raw)
        
    
# raw = Path(path).read_bytes().decode("utf-8-sig", errors="replace")
# try:
#     msgspec.json.decode(raw)
#     print('yes')
# except msgspec.DecodeError:
#     print('no')
    # # Attempt to fix the error
    # cleaned = jr.repair_json(raw, skip_json_loads=True).strip()
    # try:
    #     res = msgspec.json.decode(cleaned)
    #     if isinstance(res, list):
    #         return res[0]
    #     return res
    # except msgspec.DecodeError as e:
    #     # print(f'[{i}] {type(e).__name__}: {e} (see below)')
    #     # print(f'Error occurs at: {path.absolute()}\n')
    #     return None
"""


if __name__ == "__main__":
    print(f'{len(load_hash2risk())=}')
    