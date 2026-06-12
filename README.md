# Android Dataset Enrichment: VirusTotal + Quark-Engine

This repository contains the processing scripts used to generate the enriched Android application dataset described in:

**"Validated and Enriched Android Application Dataset: Integration of VirusTotal and Quark-Engine Intelligence"** (Data in Brief, 2026)

## Repository Structure

### 01_virustotal/
| Script | Purpose |
|--------|---------|
| `submit_to_virustotal.py` | Submit APK hashes to VirusTotal API |
| `parse_api.py` | Parse raw VT JSON responses |
| `create_vt_extensive_dataset.py` | Generate `vt_lightweight.csv` |

### 02_quark_engine/
| Script | Purpose |
|--------|---------|
| `quark_files.py` | Run Quark-Engine on APK files |
| `qk_rescan.py` | Rescan timed-out APKs (10-min timeout) |
| `create_qk_extensive_dataset.py` | Generate `qk_extensive_features.csv` |

### 03_merge_and_validate/
| Script | Purpose |
|--------|---------|
| `create_paper_summary_dataset.py` | Merge VT + QE into summary dataset |
| `create_validated_dataset.py` | Generate k=1..5 validated subsets |
| `create_balanced_dataset.py` | Create balanced subsets (optional) |

### 04_analysis/
| Script | Purpose |
|--------|---------|
| `visualize.py` | Generate all figures (1-6) |
| `compute_summary_stats.py` | Generate Table 5 (descriptive stats) |
| `comparative_study.py` | Cross-source agreement (Cohen's κ) |
| `trend_analyze.py` | Temporal trend analysis (Figure 3) |
| `malicious_distribution.py` | Malicious count distribution (Figure 2) |

### utils/
| Script | Purpose |
|--------|---------|
| `calculate_hash.py` | Compute MD5 hashes |
| `dump_pkg2hash_dict.py` | Create pkgname → MD5 mapping |
| `dump_malicious_counts.py` | Export malicious counts |
| `utility.py` | Common helper functions |


## Pipeline Order

To reproduce the full dataset from scratch, run scripts in this order:

### Phase 1: VirusTotal Collection

python 01_virustotal/submit_to_virustotal.py

python 01_virustotal/parse_api.py

python 01_virustotal/create_vt_extensive_dataset.py

### Phase 2: Quark-Engine Collection
python 02_quark_engine/quark_files.py

python 02_quark_engine/qk_rescan.py

python 02_quark_engine/create_qk_extensive_dataset.py

### Phase 3: Merge and Validate
python 03_merge_and_validate/create_paper_summary_dataset.py

python 03_merge_and_validate/create_validated_dataset.py

### Phase 4: Generate Analysis (optional)
python 04_analysis/compute_summary_stats.py

python 04_analysis/visualize.py

python 04_analysis/comparative_study.py


## Key Output Files

| Script | Output |
|--------|--------|
| `create_vt_extensive_dataset.py` | `vt_lightweight.csv` |
| `create_qk_extensive_dataset.py` | `qk_extensive_features.csv` |
| `create_paper_summary_dataset.py` | `paper_summary_dataset.csv` |
| `create_validated_dataset.py` | `val_dataset_t1.csv` ... `t5.csv` |

## Requirements
pip install pandas numpy scikit-learn matplotlib seaborn requests vt-py tqdm

Or use the provided requirements.txt.

## Test Scripts (Not required for reproduction)
The following scripts are for testing/debugging:
- All `*_test.py` files
- `debug_*.py`
- `ai.py` / `*_ai.py`
- `async_vt_teest.py`

## Citation

Mohsen, F., Zhang, Y., Gultekin, A.M., Bisgin, H., Buchta, K. (2026). Validated and Enriched Android Application Dataset: Integration of VirusTotal and Quark-Engine Intelligence. *Data in Brief*. DOI: 10.34894/XV84Z8

## License

CC BY 4.0
