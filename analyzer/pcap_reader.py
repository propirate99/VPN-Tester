"""
PCAP Reader for VajraNet AI.
Parses PCAP/PCAPNG files, extracts packet headers, timestamps, protocol statistics, and endpoints.
"""

import os
from typing import Dict, Any, List
from scapy.all import rdpcap, IP, IPv6, UDP


def read_pcap(file_path: str) -> Dict[str, Any]:
    """
    Read a PCAP or PCAPNG file and extract essential metadata and packet list.
    Handles corrupt or empty files gracefully.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        raise ValueError(f"Failed to parse PCAP file: {str(e)}")

    total_packets = len(packets)
    if total_packets == 0:
        return {
            "total_packets": 0,
            "duration": 0.0,
            "start_time": 0.0,
            "end_time": 0.0,
            "endpoints": [],
            "protocols": {},
            "packets": []
        }

    timestamps = []
    endpoints = set()
    protocols = {"ESP": 0, "IKE": 0, "UDP": 0, "TCP": 0, "OTHER": 0}
    parsed_packets: List[Dict[str, Any]] = []

    for pkt in packets:
        pkt_time = float(pkt.time)
        timestamps.append(pkt_time)

        src_ip = None
        dst_ip = None
        ip_proto = None

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_proto = pkt[IP].proto
            endpoints.add(f"{src_ip} <-> {dst_ip}")
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            ip_proto = pkt[IPv6].nh
            endpoints.add(f"{src_ip} <-> {dst_ip}")

        # Classify protocol
        proto_name = "OTHER"
        src_port = None
        dst_port = None

        # Check for ESP (IP Protocol 50)
        if ip_proto == 50 or pkt.haslayer("ESP"):
            proto_name = "ESP"
            protocols["ESP"] += 1
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if src_port in (500, 4500) or dst_port in (500, 4500):
                proto_name = "IKE"
                protocols["IKE"] += 1
            else:
                proto_name = "UDP"
                protocols["UDP"] += 1
        elif pkt.haslayer("TCP"):
            proto_name = "TCP"
            protocols["TCP"] += 1
        else:
            protocols["OTHER"] += 1

        parsed_packets.append({
            "timestamp": pkt_time,
            "length": len(pkt),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_name,
            "raw_packet": pkt
        })

    start_time = min(timestamps) if timestamps else 0.0
    end_time = max(timestamps) if timestamps else 0.0
    duration = round(end_time - start_time, 3)

    return {
        "total_packets": total_packets,
        "duration": duration,
        "start_time": start_time,
        "end_time": end_time,
        "endpoints": sorted(list(endpoints)),
        "protocols": protocols,
        "packets": parsed_packets
    }
