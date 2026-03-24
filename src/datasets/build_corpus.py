from pathlib import Path
import pandas as pd
from .csic2010_loader import load_csic2010
from .httpparams_loader import load_httpparams
from .ecml_loader import load_ecml_pkdd
from .xss_loader import load_xss

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed"

def main():
    OUT.mkdir(parents=True, exist_ok=True)

    # L1 corpus (anomaly): combine CSIC + HTTPParams if available
    l1_parts = []
    # Support both original folder name 'csic2010' and the CSV variant folder
    csic_dir = RAW / "csic2010"
    if not csic_dir.exists():
        alt_csic = RAW / "csic_database.csv"
        if alt_csic.exists():
            csic_dir = alt_csic
    if csic_dir.exists():
        df_csic = load_csic2010(csic_dir)
        if not df_csic.empty:
            l1_parts.append(df_csic[["payload","label_anomaly"]])

    # HTTPParams: support both 'httpparams' and the 'httpparams_dataset.csv/payload_full.csv' layout
    hp_dir = RAW / "httpparams"
    if not hp_dir.exists():
        alt_hp = RAW / "httpparams_dataset.csv" / "payload_full.csv"
        if alt_hp.exists():
            hp_dir = alt_hp
    if hp_dir.exists():
        df_hp = load_httpparams(hp_dir)
        if not df_hp.empty:
            # if no labels, it becomes 0; better to ensure labels exist for real evaluation
            l1_parts.append(df_hp[["payload","label_anomaly"]])

    if l1_parts:
        l1 = pd.concat(l1_parts, ignore_index=True).dropna()
        l1.to_csv(OUT / "l1_anomaly.csv", index=False)
        print("Wrote", OUT / "l1_anomaly.csv", "rows=", len(l1))
    else:
        print("No L1 datasets found. Put CSIC2010 and/or HTTPParams into data/raw/")

    # L2 corpus (threat types): combine ECML/PKDD + XSS + HTTPParams if type labels exist
    l2_parts = []

    ecml_dir = RAW / "ecml_pkdd"
    if ecml_dir.exists():
        df_ecml = load_ecml_pkdd(ecml_dir)
        if not df_ecml.empty:
            l2_parts.append(df_ecml[["raw_text","label_type"]])

    # XSS dataset: support both 'xss' and 'XSS_dataset.csv' folder
    xss_dir = RAW / "xss"
    if not xss_dir.exists():
        alt_xss = RAW / "XSS_dataset.csv"
        if alt_xss.exists():
            xss_dir = alt_xss
    if xss_dir.exists():
        df_xss = load_xss(xss_dir)
        if not df_xss.empty:
            l2_parts.append(df_xss[["raw_text","label_type"]])

    # HTTPParams may contain typed labels; reuse if present
    if hp_dir.exists():
        df_hp = load_httpparams(hp_dir)
        if not df_hp.empty and (df_hp["label_type"].astype(str).str.len().sum() > 0):
            tmp = pd.DataFrame()
            tmp["raw_text"] = df_hp["payload"].astype(str)
            tmp["label_type"] = df_hp["label_type"].astype(str)
            l2_parts.append(tmp)

    if l2_parts:
        l2 = pd.concat(l2_parts, ignore_index=True).dropna()
        # normalize label_type: keep 'Valid' for benign
        l2["label_type"] = l2["label_type"].replace({"benign":"Valid","normal":"Valid","0":"Valid"})
        l2.to_csv(OUT / "l2_threat.csv", index=False)
        print("Wrote", OUT / "l2_threat.csv", "rows=", len(l2))
    else:
        print("No L2 datasets found. Put ECML/PKDD and/or XSS into data/raw/")

if __name__ == "__main__":
    main()
