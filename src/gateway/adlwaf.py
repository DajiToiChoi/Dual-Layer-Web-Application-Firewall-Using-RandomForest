from dataclasses import dataclass
from typing import Dict, Any, Optional
import joblib
import numpy as np
from ..features.l1_features import extract_l1_ratios

@dataclass
class ReqView:
    method: str
    path: str
    headers: Dict[str, str]
    body: str
    query: str = ""

class ADLWAF:
    def __init__(self, l1_model_path: str, l2_model_path: str):
        # Layer 1: supervised RandomForest classifier (0 normal, 1 anomaly)
        self.l1 = joblib.load(l1_model_path)
        self.l2 = joblib.load(l2_model_path)  # TF-IDF + SVM (Pipeline)

    def _l1_vector(self, payload: str) -> np.ndarray:
        feats = extract_l1_ratios(payload)
        return np.array([[feats["alnum_ratio"], feats["badwords_ratio"],
                          feats["special_ratio"], feats["illegal_special_ratio"]]], dtype=float)

    def l1_predict(self, req: ReqView) -> Dict[str, Any]:
        payload = f"{req.method} {req.path}?{req.query}\n{req.headers}\n\n{req.body}"
        X = self._l1_vector(payload)

        # RandomForest: predict returns 0 (normal) or 1 (anomaly)
        pred = int(self.l1.predict(X)[0])
        is_anom = pred == 1

        # Use probability of anomaly class as anomaly_score if available
        anomaly_score: float
        raw_prob: Optional[float] = None
        if hasattr(self.l1, "predict_proba"):
            proba = self.l1.predict_proba(X)[0]
            # assume class '1' corresponds to anomaly
            if self.l1.classes_[1] == 1:
                raw_prob = float(proba[1])
            else:
                # fallback: look up index of class 1
                idx = list(self.l1.classes_).index(1)
                raw_prob = float(proba[idx])
            anomaly_score = raw_prob
        else:
            # fallback: just use 1.0 for anomaly, 0.0 for normal
            anomaly_score = 1.0 if is_anom else 0.0

        return {
            "is_anomaly": is_anom,
            "anomaly_score": float(anomaly_score),
            "raw_decision": raw_prob,
        }

    def l2_predict_type(self, req: ReqView) -> str:
        raw_text = f"{req.method} {req.path}?{req.query}\n{req.headers}\n\n{req.body}"
        return str(self.l2.predict([raw_text])[0])

    def inspect(self, req: ReqView) -> Dict[str, Any]:
        l1 = self.l1_predict(req)
        if not l1["is_anomaly"]:
            return {"blocked": False, "reason": "L1 normal", "l1": l1, "l2_type": ""}

        # If anomaly, run L2
        l2_type = self.l2_predict_type(req)
        if l2_type != "Valid":
            return {"blocked": True, "reason": f"L2 threat={l2_type}", "l1": l1, "l2_type": l2_type}
        return {"blocked": False, "reason": "Benign anomaly (L2=Valid)", "l1": l1, "l2_type": l2_type}
