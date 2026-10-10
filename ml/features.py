"""
ML Feature representation and serialization for VajraNet AI.
"""

from typing import Dict, Any, List

FEATURE_NAMES = [
    "packet_count",
    "avg_packet_size",
    "packet_rate",
    "ike_failure_count",
    "rekey_count",
    "flow_duration",
    "spi_changes"
]


def prepare_feature_vector(features: Dict[str, Any]) -> List[float]:
    """
    Convert a dictionary of features into a normalized float array for Scikit-learn models.
    """
    return [
        float(features.get("packet_count", 0)),
        float(features.get("avg_packet_size", 0.0)),
        float(features.get("packet_rate", 0.0)),
        float(features.get("ike_failure_count", 0)),
        float(features.get("rekey_count", 0)),
        float(features.get("flow_duration", 0.0)),
        float(features.get("spi_changes", 0))
    ]
