# VajraNet AI — Architecture Document

## Overview

VajraNet AI is a non-intrusive, evidence-based IPsec VPN security analyzer. It evaluates VPN packet captures (PCAP/PCAPNG) and configuration baselines, determines cryptographic and policy posture, detects traffic anomalies, and calculates actionable risk scores without breaking encryption.

---

## 🏗️ System Components

```text
               VAJRANET AI
                    ↓
         Upload authorized PCAP
                    ↓
           Analyze VPN traffic
          (IKEv2 & ESP parser)
                    ↓
            Extract evidence
                    ↓
           Security assessment
        (Rule engine & policy)
                    ↓
             Risk calculation
                    ↓
          ┌─────────┴─────────┐
          ↓                   ↓
    Threat Matrix         Timeline
          ↓                   ↓
          └─────────┬─────────┘
                    ↓
             Recommendations
                    ↓
             Security Report
```

1. **PCAP Analyzer (`analyzer/`):**
   - Ingests `.pcap` / `.pcapng` files using Scapy.
   - Extracts packet headers, timestamps, protocol counters, and IP endpoints.
   - Parses IKEv2 exchanges (UDP 500/4500) and ESP traffic (IP Protocol 50).
   - Generates SA lifecycle timeline and statistical feature vectors.

2. **Security Rules Engine (`security/`):**
   - Evaluates findings against policy baselines defined in `policy.yaml`.
   - Checks Perfect Forward Secrecy (PFS), anti-replay protection, cryptographic algorithms, and SA lifetimes.
   - Computes deterministic risk scores (0–100) and risk levels (LOW, MEDIUM, HIGH, CRITICAL).

3. **Machine Learning Anomaly Detection (`ml/`):**
   - Evaluates feature vectors using an Isolation Forest baseline model.
   - Detects traffic bursts, sequence disruptions, and negotiation storms.

4. **Backend API (`backend/`):**
   - Built with FastAPI providing RESTful endpoints (`/upload`, `/analyze`, `/anomaly`, `/health`).
   - Persists assessment history in SQLite.

5. **Dashboard (`dashboard/`):**
   - Built with Streamlit for rapid, interactive visualization of risk, timeline, threat matrix, and report export.

---

## 👥 Module Ownership

- **M1:** Overall architecture, integration, schema management.
- **M2:** strongSwan VPN lab, IKEv2/ESP protocol validation, test captures.
- **M3:** PCAP reader, Wireshark filters, packet header parsing.
- **M4:** Security policies, rule engine, risk scoring formulas.
- **M5:** FastAPI backend, database schemas, API routing.
- **M6:** Streamlit UI, timeline views, ML anomaly models.
