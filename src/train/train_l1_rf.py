from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
)

from ..features.l1_features import extract_l1_ratios

ROOT = Path(__file__).resolve().parents[2]
IN_CSV = ROOT / "data" / "processed" / "l1_anomaly.csv"
OUT_MODEL = ROOT / "models" / "l1_rf.joblib"


def build_X(df: pd.DataFrame) -> np.ndarray:
    """
    Build feature matrix for L1 from payload using the same ratios as in the paper:
    - alnum_ratio
    - badwords_ratio
    - special_ratio
    - illegal_special_ratio
    """
    rows = []
    for p in df["payload"].astype(str).tolist():
        f = extract_l1_ratios(p)
        rows.append(
            [
                f["alnum_ratio"],
                f["badwords_ratio"],
                f["special_ratio"],
                f["illegal_special_ratio"],
            ]
        )
    return np.array(rows, dtype=float)


def main():
    if not IN_CSV.exists():
        raise SystemExit(f"Missing {IN_CSV}. Run: python -m src.datasets.build_corpus")

    df = pd.read_csv(IN_CSV)
    if "label_anomaly" not in df.columns:
        raise SystemExit("l1_anomaly.csv must have label_anomaly column (0 normal / 1 anomaly).")

    X = build_X(df)
    y = df["label_anomaly"].astype(int).values  # 0 = normal, 1 = anomaly

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Layer 1: Random Forest classifier (replacement for the DT in the paper)
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("L1 RandomForest (anomaly vs normal) evaluation on held-out test:")
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Precision:", precision_score(y_test, y_pred, zero_division=0))
    print("Recall:", recall_score(y_test, y_pred, zero_division=0))
    print(classification_report(y_test, y_pred, digits=4))

    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUT_MODEL)
    print("Saved:", OUT_MODEL)


if __name__ == "__main__":
    main()




