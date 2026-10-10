"""
Anomaly detector for VajraNet AI.
Evaluates traffic feature vector against the Isolation Forest model and baseline thresholds.
"""

import os
import pickle
import numpy as np
from typing import Dict, Any, List
from .features import prepare_feature_vector

MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_model.pkl")


def load_or_train_model():
    """Load pre-trained model or initialize default model."""
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass

    from .train import train_model
    train_model()
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def detect_anomalies(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run anomaly detection on extracted traffic features.
    Returns list of identified behavioral anomalies.
    """
    anomalies = []
    vec = prepare_feature_vector(features)
    X = np.array([vec])

    try:
        model = load_or_train_model()
        prediction = model.predict(X)[0]  # -1 indicates anomaly, 1 indicates inlier
        anomaly_score = float(model.decision_function(X)[0])

        if prediction == -1:
            anomalies.append({
                "type": "STATISTICAL_OUTLIER",
                "severity": "HIGH",
                "description": "Traffic profile deviates significantly from baseline VPN behavior.",
                "score": round(anomaly_score, 4),
                "indicators": [
                    f"Packet rate: {features.get('packet_rate')} pkts/sec",
                    f"IKE failures: {features.get('ike_failure_count')}",
                    f"SPI changes: {features.get('spi_changes')}"
                ]
            })
    except Exception:
        pass

    # Heuristic anomaly checks
    if features.get("packet_rate", 0) > 1000:
        anomalies.append({
            "type": "TRAFFIC_BURST_FLOOD",
            "severity": "MEDIUM",
            "description": f"Abnormally high packet rate detected ({features.get('packet_rate')} pkts/sec)."
        })

    if features.get("ike_failure_count", 0) > 5:
        anomalies.append({
            "type": "IKE_NEGOTIATION_STORM",
            "severity": "HIGH",
            "description": f"Frequent repeated IKE negotiation failures ({features.get('ike_failure_count')} attempts)."
        })

    return anomalies
