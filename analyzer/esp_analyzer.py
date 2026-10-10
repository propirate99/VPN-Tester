"""
ESP Analyzer for VajraNet AI.
Extracts Encapsulating Security Payload (ESP) packet metadata, SPIs, sequence numbers,
and monitors sequence numbers for replay anomalies without decrypting payloads.
"""

from typing import Dict, Any, List
import struct


def analyze_esp_packets(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Inspect ESP packets to extract SPIs, sequence numbers, and replay metrics.
    """
    esp_packets = [p for p in packets if p.get("protocol") == "ESP"]
    spis = set()
    sequence_numbers_by_spi: Dict[str, List[int]] = {}
    duplicate_seq_count = 0
    out_of_order_count = 0
    total_bytes = 0

    for p in esp_packets:
        raw = p.get("raw_packet")
        total_bytes += p.get("length", 0)

        spi_val = None
        seq_num = None

        try:
            # Extract ESP header from raw packet if available
            # ESP header starts with 4-byte SPI followed by 4-byte Sequence Number
            if raw.haslayer("ESP"):
                spi_val = hex(raw["ESP"].spi)
                seq_num = raw["ESP"].seq
            else:
                # Raw payload inspection
                raw_bytes = bytes(raw)
                # Search for IP payload
                if raw.haslayer("IP"):
                    payload = bytes(raw["IP"].payload)
                    if len(payload) >= 8:
                        spi_int, seq_int = struct.unpack("!II", payload[:8])
                        spi_val = hex(spi_int)
                        seq_num = seq_int
        except Exception:
            pass

        if spi_val:
            spis.add(spi_val)
            if spi_val not in sequence_numbers_by_spi:
                sequence_numbers_by_spi[spi_val] = []

            if seq_num is not None:
                seq_list = sequence_numbers_by_spi[spi_val]
                if seq_num in seq_list:
                    duplicate_seq_count += 1
                elif seq_list and seq_num < seq_list[-1]:
                    out_of_order_count += 1
                seq_list.append(seq_num)

    replay_issue_detected = duplicate_seq_count > 0

    return {
        "packet_count": len(esp_packets),
        "total_bytes": total_bytes,
        "spis": sorted(list(spis)),
        "spi_count": len(spis),
        "duplicate_seq_count": duplicate_seq_count,
        "out_of_order_count": out_of_order_count,
        "replay_issue_detected": replay_issue_detected,
        "mode": "Tunnel" if len(esp_packets) > 0 else "None"
    }
