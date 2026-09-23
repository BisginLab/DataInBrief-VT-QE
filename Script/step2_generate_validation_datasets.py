#!/usr/bin/env python3
"""
Script 2: Generate the 13 validation datasets from validation_source.csv.

Outputs (13 datasets + 1 issue file + 1 manifest):

    VT-only (5):        vt_validated_k1.csv ... vt_validated_k5.csv
    Consensus (5):      consensus_validated_k1.csv ... consensus_validated_k5.csv
    QE-only (1):        qe_validated.csv
    Majority vote (1):  majority_vote_validated.csv
    Cleanlab (1):       cleanlab_validated.csv
    Issues:             cleanlab_label_issues.csv
    Manifest:           validation_manifest.json

All 13 validation datasets share the same output schema:

    pkgname, <47 original features>, status

The test set is never touched.

Important methodological distinction:

    VT/QE-based methods:
        Use external/enrichment signals to retain samples where the
        original label agrees with independent evidence.

    Cleanlab:
        Uses only the 47 original features and out-of-fold model
        probabilities to identify samples whose labels appear
        inconsistent with the feature distribution.

Cleanlab therefore does NOT use any of the nine enrichment features.
"""


import os
import sys
import json

import numpy as np
import pandas as pd

import sklearn
import xgboost
import cleanlab

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import cross_val_predict, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from xgboost import XGBClassifier
from cleanlab.filter import find_label_issues


# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = "/scratch/p288320/dataset1"

INPUT_FILE = f"{DATA_DIR}/validation_source.csv"
MANIFEST_FILE = f"{DATA_DIR}/validation_manifest.json"

RANDOM_STATE = 42
N_CV_FOLDS = 5

# ------------------------------------------------------------
# Diagnostic-only categorical cardinality threshold
# ------------------------------------------------------------
# This is NOT a methodological restriction.
# Features exceeding this value are still used by Cleanlab.
MAX_CATEGORICAL_CARDINALITY = 200


# ============================================================
# FEATURE DEFINITIONS
# ============================================================

# The 47 original features used by all non-augmented models.
ORIGINAL_FEATURES = [
    "DevRegisteredDomain", "LenDescription", "LenWhatsNew",
    "ReviewsAverage", "CurrentVersion", "Genre", "ContentRating",
    "LastUpdated", "LenTitle", "AndroidVersion", "DeveloperCategory",
    "isSpamming", "net", "intent", "bluetooth", "app", "provider",
    "speech", "nfc", "media", "hardware", "google", "os",
    "CALENDAR", "CAMERA", "CONTACTS", "LOCATION", "MICROPHONE",
    "PHONE", "SENSORS", "SMS", "STORAGE",
    "FourStarRatings", "ThreeStarRatings", "FiveStarRatings",
    "OneStarRatings", "TwoStarRatings", "lowest_android_version",
    "highest_android_version", "paid", "file_size",
    "max_downloads_log", "developer_email", "privacy_policy_link",
    "developer_address", "developer_website", "days_since_last_update",
]


# The nine non-constant enrichment features.
#
# IMPORTANT:
# These are used to construct VT/QE-based validation datasets,
# but MUST NOT be used as Cleanlab input features.
ENRICHMENT_FEATURES = [
    "malicious_count", "undetected_count", "certificate_life_days",
    "file_duration_days", "times_submitted", "threat_level",
    "weighted_conf_sum", "permission_n", "avg_weight",
]


# Constant enrichment feature removed in Script 1.
EXCLUDED_CONSTANT_FEATURE = "aggregated_risk_score"


LABEL = "status"
ID_COL = "pkgname"


# ============================================================
# VALIDATION RULES
# ============================================================

VT_THRESHOLDS = [1, 2, 3, 4, 5]

# Majority vote always uses k=3 for VT.
MAJORITY_VOTE_THRESHOLD = 3


# QE signal definitions.
QE_RISKY = {"Moderate Risk", "High Risk"}
QE_LOW = {"Low Risk"}


# Output schema shared by all 13 validation datasets.
OUTPUT_COLUMNS = [ID_COL] + ORIGINAL_FEATURES + [LABEL]


# ============================================================
# CLEANLAB CONFIGURATION
# ============================================================

CLEANLAB_MODEL_CONFIG = {
    "classifier": "XGBClassifier",
    "n_estimators": 100,
    "max_depth": 3,
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
    "eval_metric": "logloss",
}

CLEANLAB_RANKING = "self_confidence"


# ============================================================
# HELPERS
# ============================================================

def load_validation_source():
    """
    Load and validate validation_source.csv.
    """

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"Missing input file: {INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    # Remove accidental pandas index columns such as "Unnamed: 0".
    df = df.loc[
        :,
        ~df.columns.astype(str).str.match(r"^Unnamed")
    ]

    # --------------------------------------------------------
    # Required columns
    # --------------------------------------------------------

    required = (
        [ID_COL, LABEL]
        + ORIGINAL_FEATURES
        + ENRICHMENT_FEATURES
    )

    missing = [
        c for c in required
        if c not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    # --------------------------------------------------------
    # Duplicate package check
    # --------------------------------------------------------

    if df[ID_COL].duplicated().any():

        n_dup = int(
            df[ID_COL].duplicated().sum()
        )

        raise ValueError(
            f"Duplicated pkgname values: {n_dup:,}"
        )

    # --------------------------------------------------------
    # Binary label check
    # --------------------------------------------------------

    if df[LABEL].isna().any():

        n_missing = int(
            df[LABEL].isna().sum()
        )

        raise ValueError(
            f"Missing values in '{LABEL}': {n_missing:,}"
        )

    unique = sorted(
        df[LABEL].unique()
    )

    if unique != [0, 1]:

        raise ValueError(
            f"Expected binary labels 0/1, found: {unique}"
        )

    df[LABEL] = df[LABEL].astype(int)

    # --------------------------------------------------------
    # Original feature check
    # --------------------------------------------------------

    if len(ORIGINAL_FEATURES) != 47:
        raise AssertionError(
            f"Expected 47 original features, "
            f"found {len(ORIGINAL_FEATURES)}"
        )

    if len(ENRICHMENT_FEATURES) != 9:
        raise AssertionError(
            f"Expected 9 enrichment features, "
            f"found {len(ENRICHMENT_FEATURES)}"
        )

    return df


def check_feature_schema(df):
    """
    Confirm the expected original/enrichment feature sets are present.

    This is an explicit safeguard against accidentally running the
    validation procedure on a differently constructed dataset.
    """

    print("\n  Feature-schema check:")

    original_missing = [
        c for c in ORIGINAL_FEATURES
        if c not in df.columns
    ]

    enrichment_missing = [
        c for c in ENRICHMENT_FEATURES
        if c not in df.columns
    ]

    if original_missing:
        raise ValueError(
            f"Missing original features: {original_missing}"
        )

    if enrichment_missing:
        raise ValueError(
            f"Missing enrichment features: {enrichment_missing}"
        )

    print(
        f"    Original features:    "
        f"{len(ORIGINAL_FEATURES)} / 47"
    )

    print(
        f"    Enrichment features:  "
        f"{len(ENRICHMENT_FEATURES)} / 9"
    )


def check_threat_levels(df):
    """
    Audit the observed threat_level values before generating any
    QE-derived validation datasets.

    Unexpected values are reported as warnings. They are not silently
    mapped to either positive or negative QE signals.
    """

    print("\n  Threat-level audit:")

    counts = (
        df["threat_level"]
        .value_counts(dropna=False)
    )

    for value, count in counts.items():

        print(
            f"    {repr(value):30s} "
            f"{count:>10,}"
        )

    # Convert non-null values to strings for comparison.
    observed = set(
        df["threat_level"]
        .dropna()
        .astype(str)
        .unique()
    )

    expected = QE_RISKY | QE_LOW

    unexpected = observed - expected

    n_missing = int(
        df["threat_level"].isna().sum()
    )

    if unexpected:

        print(
            "\n  WARNING: unexpected threat_level values "
            "were found:"
        )

        for value in sorted(unexpected):
            print(
                f"    {repr(value)}"
            )

        print(
            "  These values will receive no QE vote "
            "(NaN) and will therefore not be treated as "
            "Low Risk or High/Moderate Risk."
        )

    else:

        print(
            "    No unexpected non-null threat_level "
            "values detected."
        )

    if n_missing > 0:

        print(
            f"    WARNING: {n_missing:,} rows have missing "
            "threat_level values."
        )

        print(
            "    Missing values receive no QE vote."
        )

    return {
        "observed_values": [
            None if pd.isna(v) else str(v)
            for v in counts.index
        ],
        "counts": {
            str(v): int(c)
            for v, c in counts.items()
        },
        "unexpected_values": sorted(unexpected),
        "missing_values": n_missing,
    }


def check_categorical_cardinality(df, feature_cols):
    """
    Print the cardinality of categorical columns before Cleanlab.

    This is diagnostic only.

    High-cardinality categorical variables increase the dimensionality
    of one-hot encoding and may substantially increase memory usage and
    runtime. They are NOT excluded from Cleanlab based on this threshold.
    """

    categorical_cols = (
        df[feature_cols]
        .select_dtypes(
            exclude=[np.number]
        )
        .columns
        .tolist()
    )

    print("\n  Categorical cardinalities:")

    cardinalities = {}

    for col in categorical_cols:

        n_unique = int(
            df[col].nunique(
                dropna=True
            )
        )

        cardinalities[col] = n_unique

        if n_unique > MAX_CATEGORICAL_CARDINALITY:

            print(
                f"    {col:35s} "
                f"{n_unique:>8,} unique values"
                f"  [WARNING: > "
                f"{MAX_CATEGORICAL_CARDINALITY}]"
            )

            print(
                f"      WARNING: '{col}' has high cardinality. "
                "This may substantially increase one-hot "
                "dimensionality and Cleanlab runtime, but "
                "the feature will NOT be excluded."
            )

        else:

            print(
                f"    {col:35s} "
                f"{n_unique:>8,} unique values"
            )

    return categorical_cols, cardinalities


def calculate_retention_statistics(
    out,
    source_df
):
    """
    Calculate dataset retention statistics relative to the complete
    validation_source.csv.

    Returns overall and class-specific retention rates.
    """

    source_removed = int(
        (source_df[LABEL] == 1).sum()
    )

    source_non_removed = int(
        (source_df[LABEL] == 0).sum()
    )

    retained_removed = int(
        (out[LABEL] == 1).sum()
    )

    retained_non_removed = int(
        (out[LABEL] == 0).sum()
    )

    source_rows = len(source_df)
    retained_rows = len(out)

    return {
        "retained_rows": retained_rows,
        "retention_pct": (
            round(
                retained_rows / source_rows * 100,
                2
            )
            if source_rows
            else 0.0
        ),

        "source_removed": source_removed,
        "retained_removed": retained_removed,
        "removed_retention_pct": (
            round(
                retained_removed / source_removed * 100,
                2
            )
            if source_removed
            else 0.0
        ),

        "source_non_removed": source_non_removed,
        "retained_non_removed": retained_non_removed,
        "non_removed_retention_pct": (
            round(
                retained_non_removed / source_non_removed * 100,
                2
            )
            if source_non_removed
            else 0.0
        ),
    }


def save_dataset(
    df,
    name,
    manifest,
    source_df,
    description
):
    """
    Save a validation dataset with the fixed output schema and update
    the manifest.
    """

    # --------------------------------------------------------
    # Schema validation
    # --------------------------------------------------------

    missing = [
        c for c in OUTPUT_COLUMNS
        if c not in df.columns
    ]

    if missing:

        raise ValueError(
            f"{name}: missing output columns: {missing}"
        )

    out = df[
        OUTPUT_COLUMNS
    ].copy()

    # --------------------------------------------------------
    # Basic integrity checks
    # --------------------------------------------------------

    if out[ID_COL].duplicated().any():

        raise ValueError(
            f"{name}: duplicated pkgname values detected."
        )

    if not set(
        out[LABEL].unique()
    ).issubset({0, 1}):

        raise ValueError(
            f"{name}: non-binary labels detected."
        )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    path = f"{DATA_DIR}/{name}.csv"

    out.to_csv(
        path,
        index=False
    )

    # --------------------------------------------------------
    # Class counts
    # --------------------------------------------------------

    n_removed = int(
        (out[LABEL] == 1).sum()
    )

    n_non_removed = int(
        (out[LABEL] == 0).sum()
    )

    # --------------------------------------------------------
    # Retention statistics
    # --------------------------------------------------------

    retention = calculate_retention_statistics(
        out,
        source_df
    )

    # --------------------------------------------------------
    # Manifest entry
    # --------------------------------------------------------

    manifest[name] = {

        "path": path,

        "description": description,

        "rows": int(len(out)),

        "removed": n_removed,

        "non_removed": n_non_removed,

        "removed_pct": (
            round(
                n_removed / len(out) * 100,
                2
            )
            if len(out)
            else 0.0
        ),

        "retention": retention,
    }

    # --------------------------------------------------------
    # Console output
    # --------------------------------------------------------

    print(
        f"  {name:35s} "
        f"{len(out):>8,} rows  "
        f"(removed={n_removed:,}, "
        f"non-removed={n_non_removed:,})"
    )

    print(
        f"    Retention: "
        f"{retention['retention_pct']:.2f}% overall | "
        f"removed={retention['removed_retention_pct']:.2f}% | "
        f"non-removed={retention['non_removed_retention_pct']:.2f}%"
    )


# ============================================================
# SIGNAL FUNCTIONS
# ============================================================

def vt_signal(
    malicious_count,
    k
):
    """
    Generate the VT signal.

    Positive:
        malicious_count >= k

    Negative:
        malicious_count == 0

    Intermediate values:
        no vote (NaN)
    """

    values = (
        pd.Series(
            malicious_count
        )
        .astype(float)
    )

    vote = pd.Series(
        np.nan,
        index=values.index,
        dtype=float
    )

    vote[
        values >= k
    ] = 1.0

    vote[
        values == 0
    ] = 0.0

    return vote


def qe_signal(
    threat_level
):
    """
    Generate the QE signal.

    Positive:
        Moderate Risk or High Risk

    Negative:
        Low Risk

    Other/missing values:
        no vote (NaN)
    """

    tl = (
        threat_level
        .astype(str)
    )

    vote = pd.Series(
        np.nan,
        index=tl.index,
        dtype=float
    )

    vote[
        tl.isin(QE_RISKY)
    ] = 1.0

    vote[
        tl.isin(QE_LOW)
    ] = 0.0

    return vote


# ============================================================
# STRATEGY BUILDERS
# ============================================================

def build_vt_only(
    df,
    k
):
    """
    Retain rows where the original label agrees with VT.
    """

    vt = vt_signal(
        df["malicious_count"],
        k
    )

    keep = (
        (
            (df[LABEL] == 1)
            & (vt == 1)
        )
        |
        (
            (df[LABEL] == 0)
            & (vt == 0)
        )
    )

    return df[
        keep
    ].copy()


def build_consensus(
    df,
    k
):
    """
    Strict consensus:

        original + VT + QE must all agree.
    """

    vt = vt_signal(
        df["malicious_count"],
        k
    )

    qe = qe_signal(
        df["threat_level"]
    )

    keep = (
        (
            (df[LABEL] == 1)
            & (vt == 1)
            & (qe == 1)
        )
        |
        (
            (df[LABEL] == 0)
            & (vt == 0)
            & (qe == 0)
        )
    )

    return df[
        keep
    ].copy()


def build_qe_only(
    df
):
    """
    Retain rows where the original label agrees with QE.
    """

    qe = qe_signal(
        df["threat_level"]
    )

    keep = (
        (
            (df[LABEL] == 1)
            & (qe == 1)
        )
        |
        (
            (df[LABEL] == 0)
            & (qe == 0)
        )
    )

    return df[
        keep
    ].copy()


def build_majority_vote(
    df
):
    """
    Majority vote among:

        1. Original label
        2. VT signal (k=3)
        3. QE signal

    At least two valid votes must agree.
    """

    original = (
        df[LABEL]
        .astype(float)
    )

    vt = vt_signal(
        df["malicious_count"],
        MAJORITY_VOTE_THRESHOLD
    )

    qe = qe_signal(
        df["threat_level"]
    )

    votes = pd.DataFrame({
        "original": original,
        "vt": vt,
        "qe": qe,
    })

    n_removed = (
        votes == 1
    ).sum(axis=1)

    n_non_removed = (
        votes == 0
    ).sum(axis=1)

    n_valid = (
        votes.notna()
    ).sum(axis=1)

    keep = (
        (
            (n_removed >= 2)
            |
            (n_non_removed >= 2)
        )
        &
        (n_valid >= 2)
    )

    return df[
        keep
    ].copy()


# ============================================================
# CLEANLAB
# ============================================================

def build_cleanlab(
    df,
    manifest
):
    """
    Cleanlab procedure:

        1. Use only the 47 original features.
        2. Generate 5-fold out-of-fold probabilities.
        3. Use Cleanlab find_label_issues().
        4. Remove flagged samples.
        5. Return cleaned data and flagged samples.

    No enrichment feature is used as a Cleanlab input feature.

    Mixed-type object columns are coerced to string before the
    sklearn pipeline is constructed, since OneHotEncoder requires
    uniformly typed inputs.
    """

    print("\n  Cleanlab feature preparation")

    feature_cols = [
        c
        for c in ORIGINAL_FEATURES
        if c in df.columns
    ]

    # --------------------------------------------------------
    # Feature-set validation
    # --------------------------------------------------------

    if len(feature_cols) != 47:

        raise AssertionError(
            f"Cleanlab expected 47 original features, "
            f"found {len(feature_cols)}."
        )

    forbidden = (
        set(feature_cols)
        .intersection(
            set(ENRICHMENT_FEATURES)
        )
    )

    if forbidden:

        raise AssertionError(
            "Cleanlab features must not include "
            f"enrichment columns, but found: "
            f"{sorted(forbidden)}"
        )

    # --------------------------------------------------------
    # Prepare X / y
    # --------------------------------------------------------

    X = df[
        feature_cols
    ].copy()

    y = df[
        LABEL
    ].to_numpy()

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # --------------------------------------------------------
    # FIX: Normalize mixed-type object columns
    # --------------------------------------------------------
    # sklearn's OneHotEncoder requires uniformly typed input.
    # Object columns that contain a mix of int/str will raise
    # a TypeError. Coerce all object columns to string first.

    for col in X.columns:

        if X[col].dtype == object:

            X[col] = X[col].astype(str)

    # --------------------------------------------------------
    # Detect feature types
    # --------------------------------------------------------

    numeric_cols = (
        X
        .select_dtypes(
            include=[np.number]
        )
        .columns
        .tolist()
    )

    categorical_cols = (
        X
        .select_dtypes(
            exclude=[np.number]
        )
        .columns
        .tolist()
    )

    print(
        f"    numeric={len(numeric_cols)}, "
        f"categorical={len(categorical_cols)}"
    )

    # Report categorical columns for transparency.
    print("    categorical columns:")

    for col in categorical_cols:

        n_unique = int(
            X[col].nunique(
                dropna=True
            )
        )

        print(
            f"      {col:35s} "
            f"{n_unique:>8,} unique"
        )

    # --------------------------------------------------------
    # Cardinality diagnostics
    # --------------------------------------------------------

    _, cardinalities = (
        check_categorical_cardinality(
            df,
            feature_cols
        )
    )

    # Store cardinalities in the manifest.
    manifest["cleanlab_categorical_cardinalities"] = (
        cardinalities
    )

    # --------------------------------------------------------
    # Preprocessing
    # --------------------------------------------------------

    numeric_pipeline = Pipeline([
        (
            "imputer",
            SimpleImputer(
                strategy="median",
                keep_empty_features=True
            )
        ),
        (
            "scaler",
            StandardScaler()
        ),
    ])

    categorical_pipeline = Pipeline([
        (
            "imputer",
            SimpleImputer(
                strategy="most_frequent"
            )
        ),
        (
            "encoder",
            OneHotEncoder(
                handle_unknown="ignore"
            )
        ),
    ])

    preprocessor = ColumnTransformer([
        (
            "numeric",
            numeric_pipeline,
            numeric_cols
        ),
        (
            "categorical",
            categorical_pipeline,
            categorical_cols
        ),
    ], remainder="drop")

    # --------------------------------------------------------
    # Cleanlab classifier
    # --------------------------------------------------------

    classifier = XGBClassifier(
        n_estimators=CLEANLAB_MODEL_CONFIG[
            "n_estimators"
        ],
        max_depth=CLEANLAB_MODEL_CONFIG[
            "max_depth"
        ],
        random_state=CLEANLAB_MODEL_CONFIG[
            "random_state"
        ],
        n_jobs=CLEANLAB_MODEL_CONFIG[
            "n_jobs"
        ],
        eval_metric=CLEANLAB_MODEL_CONFIG[
            "eval_metric"
        ],
    )

    model = Pipeline([
        (
            "preprocessor",
            preprocessor
        ),
        (
            "classifier",
            classifier
        ),
    ])

    # --------------------------------------------------------
    # Stratified OOF CV
    # --------------------------------------------------------

    cv = StratifiedKFold(
        n_splits=N_CV_FOLDS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    print(
        f"\n    Computing out-of-fold probabilities "
        f"({N_CV_FOLDS}-fold CV)..."
    )

    pred_probs = cross_val_predict(
        model,
        X,
        y,
        cv=cv,
        method="predict_proba",
        n_jobs=1,
    )

    # --------------------------------------------------------
    # Probability sanity check
    # --------------------------------------------------------

    if pred_probs.shape != (
        len(df),
        2
    ):

        raise ValueError(
            f"Unexpected probability shape: "
            f"{pred_probs.shape}"
        )

    if not np.isfinite(
        pred_probs
    ).all():

        raise ValueError(
            "Cleanlab received non-finite predicted "
            "probabilities."
        )

    row_sums = (
        pred_probs.sum(axis=1)
    )

    if not np.allclose(
        row_sums,
        1.0,
        atol=1e-6
    ):

        raise ValueError(
            "OOF probability rows do not sum to 1."
        )

    print(
        "    OOF probability generation complete."
    )

    # --------------------------------------------------------
    # Cleanlab
    # --------------------------------------------------------

    print(
        "\n    Running Cleanlab find_label_issues..."
    )

    label_issues = find_label_issues(
        labels=y,
        pred_probs=pred_probs,
        return_indices_ranked_by=CLEANLAB_RANKING,
    )

    label_issues = np.asarray(
        label_issues
    )

    if label_issues.dtype == bool:

        label_issues = np.flatnonzero(
            label_issues
        )

    else:

        label_issues = (
            label_issues.astype(int)
        )

    # --------------------------------------------------------
    # Validate issue indices
    # --------------------------------------------------------

    if len(label_issues) > len(df):

        raise ValueError(
            "Cleanlab returned more label issues "
            "than input rows."
        )

    if len(np.unique(label_issues)) != len(
        label_issues
    ):

        raise ValueError(
            "Cleanlab returned duplicate issue indices."
        )

    if (
        len(label_issues) > 0
        and (
            label_issues.min() < 0
            or label_issues.max() >= len(df)
        )
    ):

        raise ValueError(
            "Cleanlab returned an invalid row index."
        )

    # --------------------------------------------------------
    # Build cleaned / issue datasets
    # --------------------------------------------------------

    clean_mask = np.ones(
        len(y),
        dtype=bool
    )

    clean_mask[
        label_issues
    ] = False

    cleaned_df = df.loc[
        clean_mask
    ].copy()

    issues_df = df.iloc[
        label_issues
    ].copy()

    # --------------------------------------------------------
    # Cleanlab statistics
    # --------------------------------------------------------

    n_issues = len(
        label_issues
    )

    issue_pct = (
        n_issues / len(y) * 100
        if len(y)
        else 0.0
    )

    issue_removed = int(
        (
            issues_df[LABEL] == 1
        ).sum()
    )

    issue_non_removed = int(
        (
            issues_df[LABEL] == 0
        ).sum()
    )

    manifest[
        "cleanlab_issue_statistics"
    ] = {

        "flagged_rows": int(
            n_issues
        ),

        "flagged_pct": round(
            issue_pct,
            2
        ),

        "flagged_removed": issue_removed,

        "flagged_non_removed": issue_non_removed,

        "retained_rows": int(
            len(cleaned_df)
        ),

        "retained_pct": round(
            len(cleaned_df)
            / len(df)
            * 100,
            2
        ),
    }

    print(
        f"\n    Flagged:  {n_issues:,} "
        f"({issue_pct:.2f}%)"
    )

    print(
        f"      removed:     {issue_removed:,}"
    )

    print(
        f"      non-removed: {issue_non_removed:,}"
    )

    print(
        f"    Retained: {len(cleaned_df):,} "
        f"({len(cleaned_df) / len(df) * 100:.2f}%)"
    )

    return (
        cleaned_df,
        issues_df
    )

# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print(
        "SCRIPT 2: GENERATE VALIDATION DATASETS"
    )
    print("=" * 70)

    # --------------------------------------------------------
    # Software versions
    # --------------------------------------------------------

    print("\nSoftware versions:")

    print(
        f"  Python:   "
        f"{sys.version.split()[0]}"
    )

    print(
        f"  pandas:   "
        f"{pd.__version__}"
    )

    print(
        f"  numpy:    "
        f"{np.__version__}"
    )

    print(
        f"  sklearn:  "
        f"{sklearn.__version__}"
    )

    print(
        f"  xgboost:  "
        f"{xgboost.__version__}"
    )

    print(
        f"  cleanlab: "
        f"{cleanlab.__version__}"
    )

    # --------------------------------------------------------
    # Load source
    # --------------------------------------------------------

    print(
        f"\nInput: {INPUT_FILE}"
    )

    df = load_validation_source()

    print(
        f"Loaded {len(df):,} rows, "
        f"{df.shape[1]} columns"
    )

    print(
        f"  Unique pkgname: "
        f"{df[ID_COL].nunique():,}"
    )

    print(
        f"  Removed:        "
        f"{(df[LABEL] == 1).sum():,}"
    )

    print(
        f"  Non-removed:    "
        f"{(df[LABEL] == 0).sum():,}"
    )

    # --------------------------------------------------------
    # Pre-generation checks
    # --------------------------------------------------------

    check_feature_schema(
        df
    )

    threat_level_audit = (
        check_threat_levels(
            df
        )
    )

    # --------------------------------------------------------
    # Manifest
    # --------------------------------------------------------

    manifest = {

        # ----------------------------------------------------
        # Reproducibility
        # ----------------------------------------------------

        "script":
            "step2_generate_validation_datasets.py",

        "source_dataset":
            "validation_source.csv",

        "source_dataset_path":
            INPUT_FILE,

        "input_rows":
            int(len(df)),

        "random_state":
            RANDOM_STATE,

        # ----------------------------------------------------
        # Dataset structure
        # ----------------------------------------------------

        "feature_counts": {

            "original_features":
                len(ORIGINAL_FEATURES),

            "enrichment_features":
                len(ENRICHMENT_FEATURES),

        },

        # ----------------------------------------------------
        # Feature handling
        # ----------------------------------------------------

        "excluded_constant_feature":
            EXCLUDED_CONSTANT_FEATURE,

        "enrichment_features":
            ENRICHMENT_FEATURES,

        "enrichment_features_excluded_from_cleanlab":
            ENRICHMENT_FEATURES,

        "cleanlab_feature_set":
            "47 original features only",

        # ----------------------------------------------------
        # Rule definitions
        # ----------------------------------------------------

        "consensus_rule":
            "3_of_3",

        "majority_rule":
            "2_of_3",

        "vt_positive_rule":
            "malicious_count >= k",

        "vt_negative_rule":
            "malicious_count == 0",

        "qe_positive_rule":
            "threat_level in "
            "{Moderate Risk, High Risk}",

        "qe_negative_rule":
            "threat_level == Low Risk",

        # ----------------------------------------------------
        # Thresholds
        # ----------------------------------------------------

        "vt_thresholds":
            VT_THRESHOLDS,

        "majority_vote_threshold":
            MAJORITY_VOTE_THRESHOLD,

        # ----------------------------------------------------
        # Cleanlab configuration
        # ----------------------------------------------------

        "cleanlab_cv_folds":
            N_CV_FOLDS,

        "cleanlab_oof":
            True,

        "cleanlab_model":
            CLEANLAB_MODEL_CONFIG,

        "cleanlab_ranking":
            CLEANLAB_RANKING,

        # ----------------------------------------------------
        # Engineering diagnostic
        # ----------------------------------------------------

        "categorical_cardinality_warning_threshold":
            MAX_CATEGORICAL_CARDINALITY,

        "categorical_cardinality_threshold_is_methodological":
            False,

        # ----------------------------------------------------
        # Threat-level audit
        # ----------------------------------------------------

        "threat_level_audit":
            threat_level_audit,

        # ----------------------------------------------------
        # Output schema
        # ----------------------------------------------------

        "output_schema":
            OUTPUT_COLUMNS,

        # ----------------------------------------------------
        # Populated during execution
        # ----------------------------------------------------

        "datasets":
            {},
    }

    # ========================================================
    # VT-ONLY
    # ========================================================

    print(
        "\n--- VT-only validation ---"
    )

    for k in VT_THRESHOLDS:

        name = (
            f"vt_validated_k{k}"
        )

        out = build_vt_only(
            df,
            k
        )

        save_dataset(
            out,
            name,
            manifest["datasets"],
            df,
            f"VT-only validation with "
            f"threshold k={k}"
        )

    # ========================================================
    # STRICT CONSENSUS
    # ========================================================

    print(
        "\n--- Strict consensus validation ---"
    )

    for k in VT_THRESHOLDS:

        name = (
            f"consensus_validated_k{k}"
        )

        out = build_consensus(
            df,
            k
        )

        save_dataset(
            out,
            name,
            manifest["datasets"],
            df,
            "Strict consensus "
            "(original+VT+QE) with "
            f"threshold k={k}"
        )

    # ========================================================
    # QE-ONLY
    # ========================================================

    print(
        "\n--- QE-only validation ---"
    )

    out = build_qe_only(
        df
    )

    save_dataset(
        out,
        "qe_validated",
        manifest["datasets"],
        df,
        "QE-only validation "
        "(original + QE)"
    )

    # ========================================================
    # MAJORITY VOTE
    # ========================================================

    print(
        "\n--- Majority vote validation ---"
    )

    out = build_majority_vote(
        df
    )

    save_dataset(
        out,
        "majority_vote_validated",
        manifest["datasets"],
        df,
        "Majority vote "
        "(>=2 of 3 signals), "
        "VT threshold fixed at "
        f"k={MAJORITY_VOTE_THRESHOLD}"
    )

    # ========================================================
    # CLEANLAB
    # ========================================================

    print(
        "\n--- Cleanlab validation ---"
    )

    cleaned_df, issues_df = (
        build_cleanlab(
            df,
            manifest
        )
    )

    save_dataset(
        cleaned_df,
        "cleanlab_validated",
        manifest["datasets"],
        df,
        "Cleanlab validation "
        "(47 original features only)"
    )

    # --------------------------------------------------------
    # Save Cleanlab issues
    # --------------------------------------------------------

    issues_path = (
        f"{DATA_DIR}/"
        "cleanlab_label_issues.csv"
    )

    issues_df.to_csv(
        issues_path,
        index=False
    )

    manifest[
        "cleanlab_issues"
    ] = {

        "path":
            issues_path,

        "rows":
            int(len(issues_df)),
    }

    print(
        f"  cleanlab_label_issues.csv "
        f"{len(issues_df):>8,} rows"
    )

    # ========================================================
    # SAVE MANIFEST
    # ========================================================

    with open(
        MANIFEST_FILE,
        "w"
    ) as f:

        json.dump(
            manifest,
            f,
            indent=2
        )

    print(
        f"\nSaved manifest: "
        f"{MANIFEST_FILE}"
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "SUMMARY: 13 validation datasets generated"
    )

    print(
        "=" * 70
    )

    for name, info in (
        manifest["datasets"].items()
    ):

        retention = info[
            "retention"
        ]

        print(
            f"  {name:35s} "
            f"{info['rows']:>8,} rows  "
            f"(removed={info['removed']:,}, "
            f"non-removed={info['non_removed']:,})"
        )

        print(
            f"    retention: "
            f"{retention['retention_pct']:.2f}% overall | "
            f"removed={retention['removed_retention_pct']:.2f}% | "
            f"non-removed={retention['non_removed_retention_pct']:.2f}%"
        )

    print(
        "\nDone."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
