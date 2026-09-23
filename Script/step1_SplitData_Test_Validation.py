import pandas as pd
from sklearn.model_selection import train_test_split

#DATA_DIR = "."

# The 9 new features
NEW_FEATURES = [
    "malicious_count",
    "undetected_count",
    "certificate_life_days",
    "file_duration_days",
    "times_submitted",
    "threat_level",
    "weighted_conf_sum",
    "permission_n",
    "avg_weight",
]

# Constant feature to remove entirely
CONSTANT_FEATURE = "aggregated_risk_score"

enriched = pd.read_csv(f"paper_summary_dataset.csv")
enriched = enriched.loc[:, ~enriched.columns.astype(str).str.match(r"^Unnamed")]

# Remove the constant feature if present
if CONSTANT_FEATURE in enriched.columns:
    enriched = enriched.drop(columns=[CONSTANT_FEATURE])

# Drop rows with missing status and enforce int type
enriched = enriched.dropna(subset=["status"])
enriched["status"] = enriched["status"].astype(int)

# Single split, seed 42, 70/30 stratified
train_df, test_df = train_test_split(
    enriched,
    test_size=0.30,
    stratify=enriched["status"],
    random_state=42,
)

# Save the three outputs
train_df.to_csv(f"validation_source.csv", index=False)
test_df.to_csv(f"test_set_with_features.csv", index=False)

test_original = test_df.drop(columns=[c for c in NEW_FEATURES if c in test_df.columns])
test_original.to_csv(f"test_set_original_features.csv", index=False)

# Report
print(f"Validation source:  {len(train_df):,} rows")
print(f"Test (with feats):  {len(test_df):,} rows, {test_df.shape[1]} columns")
print(f"Test (orig feats):  {len(test_original):,} rows, {test_original.shape[1]} columns")
print()
print("Status distribution in test set:")
print(test_df["status"].value_counts(normalize=True))
print()
print("Columns in validation source:")
print(train_df.columns.tolist())