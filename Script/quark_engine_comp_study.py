import json
import os
from pathlib import Path  # Needed for file path operations
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Define base directories for the two report sets
QUARK_PATH = "/shared/frankzha/data/quark_engine_results"
VT_PATH = "/shared/frankzha/data/new_json_reports_ai/"

# --- Collect common file names ---
quark_base = Path(QUARK_PATH)
quark_files = {f.relative_to(quark_base) for f in quark_base.rglob("*.json")}
print("Quark-engine files:", len(quark_files))

vt_base = Path(VT_PATH)
vt_files = {f.relative_to(vt_base) for f in vt_base.rglob("*.json")}
print("VirusTotal files:", len(vt_files))

common_files = quark_files.intersection(vt_files)
print("Common files:", len(common_files))

data_records = []
count = 0
for file in common_files:
    if count >= 10000:
        break
    quark_filepath = os.path.join(QUARK_PATH, str(file))
    vt_filepath = os.path.join(VT_PATH, str(file))
    try:
        with open(quark_filepath, 'r', encoding='utf-8') as qf, open(vt_filepath, 'r', encoding='utf-8') as vf:
            quark_report = json.load(qf)
            vt_report = json.load(vf)
        threat_level = quark_report.get('threat_level', None)
        total_score = quark_report.get('total_score')
        size_quark = quark_report.get('size_bytes')
        crimes = quark_report.get('crimes', [])
        crime_count = len(crimes)
        vt_attributes = vt_report.get('data', {}).get('attributes', {})
        stats = vt_attributes.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        total_scans = sum(stats.values())
        engine_detection_ratio = (malicious_count + suspicious_count) / total_scans if total_scans > 0 else 0
        size_vt = vt_attributes.get('size')
        androguard = vt_attributes.get('androguard', {})
        permission_details = androguard.get('permission_details', {})
        dangerous_permission_count = sum(1 for perm in permission_details.values() if perm.get('permission_type') == 'dangerous')
        data_records.append({
            'threat_level': threat_level,
            'total_score': total_score,
            'crime_count': crime_count,
            'malicious_count': malicious_count,
            'suspicious_count': suspicious_count,
            'engine_detection_ratio': engine_detection_ratio,
            'size_quark': size_quark,
            'size_vt': size_vt,
            'dangerous_permission_count': dangerous_permission_count
        })
        count += 1
    except Exception as e:
        print(f"Error processing {file}: {e}")

# Convert the records to a DataFrame for analysis
df = pd.DataFrame(data_records)
print("DataFrame head:")
print(df.head())

# --- Visualization & Saving Graphs ---

# 1. Scatter Plot: VirusTotal Malicious Count vs. Quark Total Score
# First, remove rows with missing or None values in these fields
scatter_df = df.dropna(subset=['malicious_count', 'total_score'])
plt.figure(figsize=(8, 6), dpi=300)
plt.scatter(scatter_df['malicious_count'], scatter_df['total_score'],
            alpha=0.6, edgecolors='w', color='teal')
plt.xlabel('VirusTotal Malicious Engine Count')
plt.ylabel('Quark Total Score')
plt.title('VT Malicious Count vs. Quark Total Score')
plt.grid(True)
plt.savefig("CS_scatter_vt_malicious_vs_quark_total_score.png")
plt.close()
print("Saved scatter plot: CS_scatter_vt_malicious_vs_quark_total_score.png")

# 2. Correlation Heatmap of Selected Numerical Features
cols_for_heatmap = [
    'total_score',
    'crime_count',
    'malicious_count',
    'engine_detection_ratio',
    'size_quark',
    'size_vt',
    'dangerous_permission_count'
]

for col in cols_for_heatmap:
    df[col] = pd.to_numeric(df[col], errors='coerce')

df_clean = df[cols_for_heatmap].dropna()

# Remove columns that have no or minimal variance (nunique <= 1), which would yield NaN in correlations
cols_to_drop = []
for col in cols_for_heatmap:
    if col in df_clean.columns and df_clean[col].nunique() <= 1:
        cols_to_drop.append(col)

if cols_to_drop:
    df_clean.drop(columns=cols_to_drop, inplace=True)
    print(f"Dropped columns with no variance: {cols_to_drop}")

remaining_cols = df_clean.columns.tolist()
if len(remaining_cols) <= 1:
    print("Not enough columns remain for a correlation matrix.")
else:
    corr_matrix = df_clean[remaining_cols].corr()

    plt.figure(figsize=(12, 10), dpi=300)
    cax = plt.matshow(corr_matrix, fignum=1, cmap="coolwarm")
    plt.colorbar(cax)
    plt.xticks(range(len(remaining_cols)), remaining_cols, rotation=45, ha='left', fontsize=9)
    plt.yticks(range(len(remaining_cols)), remaining_cols, fontsize=9)
    for i in range(len(remaining_cols)):
        for j in range(len(remaining_cols)):
            val = corr_matrix.iloc[i, j]
            color = 'white' if abs(val) > 0.5 else 'black'
            plt.text(j, i, f"{val:.2f}", ha='center', va='center', color=color, fontsize=8)
    plt.title("Correlation Heatmap of Relevant Attributes", y=1.15, fontsize=16)
    plt.tight_layout()
    plt.savefig("CS_correlation_heatmap.png")
    plt.close()
    print("Saved relevant correlation heatmap: relevant_correlation_heatmap_fixed.png")

# 3. Histogram of Threat Levels
plt.figure(figsize=(6, 4), dpi=300)
# Count occurrences of threat levels; drop missing values, if any
threat_counts = df['threat_level'].value_counts()
plt.bar(threat_counts.index[::-1], threat_counts.values[::-1], color='mediumseagreen', edgecolor='black')
plt.xlabel('Threat Level')
plt.ylabel('Frequency')
plt.title('Distribution of Threat Levels')
plt.savefig("CS_histogram_threat_levels.png")
plt.close()
print("Saved histogram: CS_histogram_threat_levels.png")

# Map threat level strings to numeric values for any further analysis
# (Customize the mapping as needed; here 'High Risk' is set equal to 'Moderate Risk')
threat_mapping = {"Low Risk": 0, "Moderate Risk": 1, "High Risk": 1}
df['threat_level_numeric'] = df['threat_level'].map(threat_mapping)
print("Threat level mapping applied.")

# --- Additional Analysis and Visualization ---

# Create a binary flag for VirusTotal malicious classification:
# 1 if malicious_count >= 1, otherwise 0.
df['vt_malicious_flag'] = (df['malicious_count'].fillna(0) + df['suspicious_count'] >= 1).astype(int)

# Create a binary risk flag from Quark-engine's threat_level:
# Assign 0 for 'Low Risk' and 1 for 'Moderate Risk' & 'High Risk'.
df['risk_flag'] = df['threat_level'].apply(lambda x: 0 if x == "Low Risk" else 1)

# 1. Bar graph: Proportion of apps flagged as malicious by VT across the three Quark-engine threat levels
# Group the data by threat level and calculate the mean of vt_malicious_flag (which is the proportion)
grouped = df.groupby('threat_level')['vt_malicious_flag'].agg(['mean', 'count']).reset_index()
grouped['percentage'] = grouped['mean'] * 100  # Convert to percentage
print("Grouped malicious proportions by threat level:")
print(grouped)

# Plot the bar graph.
plt.figure(figsize=(8, 6), dpi=300)
# Colors chosen to denote risk: green (low), orange (moderate), red (high)
colors = ['green' if level=="Low Risk" else 'orange' if level=="Moderate Risk" else 'red' 
          for level in grouped['threat_level']]
plt.bar(grouped['threat_level'], grouped['percentage'], color=colors, edgecolor='black')
plt.xlabel('Threat Level (Quark-engine)')
plt.ylabel('Percentage of apps flagged as malicious by VT')
plt.title('Proportion of Apps Flagged as Malicious by VT\nacross Quark-engine Threat Levels')
plt.ylim(0, 100)
# Add text annotations above each bar showing the percentage
for idx, row in grouped.iterrows():
    plt.text(idx, row['percentage'] + 2, f"{row['percentage']:.1f}%", ha='center', va='bottom', fontsize=10)
plt.tight_layout()
plt.savefig("CS_bargraph_vt_malicious_by_threat.png")
plt.close()

# 2. Compute and print the correlation between the risk_flag and vt_malicious_flag
# This measures the association between Quark-engine risk (low vs. moderate/high) and VT's binary malicious flag.
correlation = df[['risk_flag', 'vt_malicious_flag']].corr().iloc[0, 1]
print(f"Correlation between (low vs. moderate/high risk) and VT malicious flag: {correlation:.3f}")
