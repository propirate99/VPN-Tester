"""
Timeline generator for VajraNet AI.
Builds Security Association (SA) lifecycle timeline from IKE events and rekeys.
"""

from typing import Dict, Any, List
from datetime import datetime


def build_sa_timeline(ike_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Construct an ordered SA lifecycle timeline from IKE event occurrences.
    """
    timeline = []
    base_time = None

    for ev in ike_events:
        ts = ev.get("timestamp", 0)
        if base_time is None:
            base_time = ts

        relative_offset = round(ts - base_time, 2)
        try:
            formatted_time = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        except Exception:
            formatted_time = f"+{relative_offset}s"

        timeline.append({
            "timestamp": formatted_time,
            "relative_seconds": relative_offset,
            "event": ev.get("exchange", "UNKNOWN"),
            "endpoints": f"{ev.get('src')}:{ev.get('src_port')} -> {ev.get('dst')}:{ev.get('dst_port')}",
            "description": _describe_event(ev.get("exchange", ""))
        })

    return timeline


def _describe_event(exchange: str) -> str:
    descriptions = {
        "IKE_SA_INIT": "Initial cryptographic parameters and Diffie-Hellman exchange negotiated.",
        "IKE_AUTH": "Mutual identity authentication and first CHILD_SA establishment.",
        "CREATE_CHILD_SA": "Additional IPsec SA created or rekeying initiated.",
        "INFORMATIONAL": "Control, keepalive (DPD), or error notification exchanged."
    }
    return descriptions.get(exchange, "IKE protocol message exchanged.")
