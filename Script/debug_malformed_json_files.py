import msgspec
import logging
from pathlib import Path
from multiprocessing import Pool, cpu_count
from tqdm import tqdm

# Replace these stubs with your actual utility imports
from utility import get_all_vt_ai_files, get_qk_files



# Directories (customize as needed)
VT_DIR = '/shared/frankzha/data/vt_ai'
QK_DIR = '/shared/frankzha/data/qk'
OUT_DIR = '/shared/frankzha/data/log_file'

# Logging configuration
def configure_logging():
    out_dir = Path(OUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=out_dir / 'scan_invalid_json.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s'
    )
    logging.info('Starting JSON validity scan')


def is_json_valid(path: Path) -> bool:
    try:
        raw = path.read_bytes().decode("utf-8-sig", errors="replace")
        msgspec.json.decode(raw)
        return True
    except (msgspec.DecodeError, UnicodeDecodeError):
        return False


def scan_pair(pair):
    vt_path, qk_path = pair
    return (
        vt_path, is_json_valid(vt_path),
        qk_path, is_json_valid(qk_path)
    )


def main():
    configure_logging()
    vt_files = {p.stem: p for p in get_all_vt_ai_files()}
    qk_files = {p.stem: p for p in get_qk_files()}
    common = sorted((vt_files[s], qk_files[s]) for s in vt_files.keys() & qk_files.keys())
    print(len(vt_files))
    print(len(qk_files))
    print(len(common))
    logging.info(f'Found {len(common)} common file pairs')

    vt_log_path = Path(OUT_DIR) / 'malformed_vt_files.txt'
    qk_log_path = Path(OUT_DIR) / 'malformed_qk_files.txt'

    with Pool(processes=cpu_count() // 2 or 1) as pool, \
         vt_log_path.open('w', encoding='utf-8') as f_vt, \
         qk_log_path.open('w', encoding='utf-8') as f_qk:
        try:
            for vt_path, vt_ok, qk_path, qk_ok in tqdm(
                pool.imap_unordered(scan_pair, common),
                total=len(common),
                desc='Scanning JSON'
            ):
                if not vt_ok:
                    f_vt.write(str(vt_path) + '\n')
                    logging.warning(f'Malformed VT JSON: {vt_path}')
                if not qk_ok:
                    f_qk.write(str(qk_path) + '\n')
                    logging.warning(f'Malformed QK JSON: {qk_path}')
        except KeyboardInterrupt:
            logging.error('Interrupted by user')
            pool.terminate()
            pool.join()
            raise

    logging.info('Scan complete')
    print(f"Scan finished. See logs in {OUT_DIR}")


if __name__ == '__main__':
    main()