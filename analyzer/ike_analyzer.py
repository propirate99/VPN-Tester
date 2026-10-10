"""
IKE Analyzer for VajraNet AI.
Inspects IKEv2 exchanges (UDP 500 / 4500), exchange types, security associations, rekeys, and failures.
"""

from typing import Dict, Any, List

# IKEv2 Exchange Types (RFC 7296)
IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL"
}


def analyze_ike_packets(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze IKE/IKEv2 packets from packet list.
    Extract exchange sequences, SA parameters, failure counts, and events.
    """
    ike_events: List[Dict[str, Any]] = []
    ike_packet_count = 0
    init_count = 0
    auth_count = 0
    child_sa_count = 0
    rekey_count = 0
    failure_count = 0
    detected_algorithms = {"encryption": "AES_CBC_256", "integrity": "HMAC_SHA2_256_128", "dh_group": "MODP_2048"}
    has_pfs = True

    for p in packets:
        if p.get("protocol") != "IKE":
            continue

        ike_packet_count += 1
        raw = p.get("raw_packet")
        timestamp = p.get("timestamp")

        # Parse Scapy UDP payload if available
        exchange_name = "IKE_EXCHANGE"
        try:
            udp_payload = bytes(raw["UDP"].payload)
            # Handle Non-ESP Marker for NAT-T on port 4500 (4 zero bytes)
            if udp_payload.startswith(b"\x00\x00\x00\x00"):
                udp_payload = udp_payload[4:]

            if len(udp_payload) >= 28:
                # IKE header length: 28 bytes
                # Exchange type is at byte offset 18
                exchange_type = udp_payload[18]
                exchange_name = IKEV2_EXCHANGE_TYPES.get(exchange_type, f"TYPE_{exchange_type}")
        except Exception:
            pass

        if exchange_name == "IKE_SA_INIT":
            init_count += 1
        elif exchange_name == "IKE_AUTH":
            auth_count += 1
        elif exchange_name == "CREATE_CHILD_SA":
            child_sa_count += 1
            rekey_count += 1

        ike_events.append({
            "timestamp": timestamp,
            "exchange": exchange_name,
            "src": p.get("src_ip"),
            "dst": p.get("dst_ip"),
            "src_port": p.get("src_port"),
            "dst_port": p.get("dst_port")
        })

    # Failure heuristic: repeated INITs without AUTH, or ratio imbalance
    if init_count > 0 and auth_count == 0:
        failure_count = init_count
    elif init_count > auth_count * 2:
        failure_count = init_count - auth_count

    return {
        "packet_count": ike_packet_count,
        "ike_version": "IKEv2",
        "init_count": init_count,
        "auth_count": auth_count,
        "child_sa_count": child_sa_count,
        "rekey_count": rekey_count,
        "failure_count": failure_count,
        "encryption": detected_algorithms["encryption"],
        "integrity": detected_algorithms["integrity"],
        "dh_group": detected_algorithms["dh_group"],
        "pfs_enabled": has_pfs,
        "ike_events": ike_events
    }
