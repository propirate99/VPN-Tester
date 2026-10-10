"""
Feature Extractor for VajraNet AI.
Extracts numerical and statistical network features for security rule validation and ML anomaly models.
"""

from typing import Dict, Any


def extract_vpn_features(
    pcap_data: Dict[str, Any],
    ike_data: Dict[str, Any],
    esp_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Extract security and traffic baseline features:
    - packet_count
    - avg_packet_size
    - packet_rate
    - ike_failure_count
    - rekey_count
    - flow_duration
    - spi_changes
    """
    total_packets = pcap_data.get("total_packets", 0)
    duration = pcap_data.get("duration", 0.0)

    packets = pcap_data.get("packets", [])
    total_length = sum(p.get("length", 0) for p in packets)
    avg_packet_size = round(total_length / total_packets, 2) if total_packets > 0 else 0.0

    packet_rate = round(total_packets / duration, 2) if duration > 0 else float(total_packets)

    ike_failure_count = ike_data.get("failure_count", 0)
    rekey_count = ike_data.get("rekey_count", 0)
    spi_changes = max(0, esp_data.get("spi_count", 0) - 1)

    return {
        "packet_count": total_packets,
        "avg_packet_size": avg_packet_size,
        "packet_rate": packet_rate,
        "ike_failure_count": ike_failure_count,
        "rekey_count": rekey_count,
        "flow_duration": duration,
        "spi_changes": spi_changes,
        "esp_packet_count": esp_data.get("packet_count", 0),
        "duplicate_seq_count": esp_data.get("duplicate_seq_count", 0)
    }
