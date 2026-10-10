"""
ML Training script for VajraNet AI using Isolation Forest.
Trains an unsupervised baseline on normal VPN traffic features.
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_model.pkl")


def generate_synthetic_normal_baseline() -> np.ndarray:
    """
    Generate synthetic baseline representing normal VPN operation:
    [packet_count, avg_packet_size, packet_rate, ike_failures, rekeys, flow_duration, spi_changes]
    """
    np.random.seed(42)
    n_samples = 200

    packet_count = np.random.uniform(500, 5000, n_samples)
    avg_packet_size = np.random.uniform(200, 1400, n_samples)
    packet_rate = np.random.uniform(10, 200, n_samples)
    ike_failures = np.zeros(n_samples)  # normal traffic has 0 failures
    rekeys = np.random.poisson(1, n_samples)
    flow_duration = np.random.uniform(30, 300, n_samples)
    spi_changes = np.random.choice([0, 1], n_samples)

    return np.column_stack([
        packet_count,
        avg_packet_size,
        packet_rate,
        ike_failures,
        rekeys,
        flow_duration,
        spi_changes
    ])


def train_model() -> None:
    """Train Isolation Forest on baseline traffic features and persist model."""
    X = generate_synthetic_normal_baseline()
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    clf.fit(X)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"Model saved successfully to {MODEL_PATH}")


if __name__ == "__main__":
    train_model()
