from pathlib import Path
import pandas as pd


def _load_from_txt(raw_dir: Path) -> pd.DataFrame:
    """
    Original CSIC 2010 format: separate text files for normal/anomalous HTTP requests.
    Each line is treated as one raw HTTP request string.
    """
    rows = []
    txt_files = list(raw_dir.glob("*.txt"))
    for fp in txt_files:
        name = fp.name.lower()
        if "normal" in name or "valid" in name:
            label = 0
        elif "anomal" in name or "attack" in name or "malicious" in name:
            label = 1
        else:
            # unknown -> skip unless you rename files
            continue

        for line in fp.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append({"payload": line, "label_anomaly": label})

    return pd.DataFrame(rows)


def _load_from_csv(raw_dir: Path) -> pd.DataFrame:
    """
    Some CSIC 2010 distributions are provided as a single CSV like 'csic_database.csv'
    with columns including:
      - 'classification' : 0/1 or 'Normal'/'Anomalous'
      - 'URL'            : the full HTTP request line
    We map classification -> label_anomaly and use URL as payload.
    """
    csv_files = list(raw_dir.glob("*.csv"))
    if not csv_files:
        return pd.DataFrame(columns=["payload", "label_anomaly"])

    df = pd.concat([pd.read_csv(fp) for fp in csv_files], ignore_index=True)

    # Try to find classification and URL columns
    cls_col = None
    url_col = None
    for c in df.columns:
        lc = c.lower()
        if lc in ("classification", "class", "label", "attack"):
            cls_col = c
        if lc in ("url", "request", "http", "payload"):
            url_col = url_col or c

    # Fallbacks
    if url_col is None:
        url_col = df.columns[-1]
    if cls_col is None:
        # If we cannot find labels, treat everything as normal (not ideal, but usable)
        out = pd.DataFrame()
        out["payload"] = df[url_col].astype(str)
        out["label_anomaly"] = 0
        return out

    def _to_label(v) -> int:
        s = str(v).strip().lower()
        if s in ("0", "normal", "benign", "valid"):
            return 0
        return 1

    out = pd.DataFrame()
    out["payload"] = df[url_col].astype(str)
    out["label_anomaly"] = df[cls_col].apply(_to_label)
    return out


def load_csic2010(raw_dir: Path) -> pd.DataFrame:
    """
    Flexible loader that supports:
      - The classic TXT-based CSIC 2010 layout.
      - The CSV-based layout (e.g. 'csic_database.csv' folder in data/raw).
    Output: DataFrame(payload, label_anomaly)
    """
    df_txt = _load_from_txt(raw_dir)
    if not df_txt.empty:
        return df_txt
    return _load_from_csv(raw_dir)

