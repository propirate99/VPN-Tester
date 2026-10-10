"""
VajraNet AI — Streamlit Cybersecurity Dashboard
Interactive UI for PCAP upload, tunnel inventory, risk scoring, threat matrix,
SA lifecycle timeline, anomaly detection, and security report export.
"""

import streamlit as st
import pandas as pd
import requests
import json
import os
import tempfile

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

st.set_page_config(
    page_title="VajraNet AI — VPN Security Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ VajraNet AI")
st.subheader("Evidence-Based IPsec VPN Security Analyzer")
st.markdown("""
Inspect authorized PCAP traffic, verify VPN configuration policies (PFS, Replay, Crypto, SAs),
detect anomalies, and generate actionable remediation reports without payload decryption.
""")

st.divider()

# Sidebar: Service Status & Information
with st.sidebar:
    st.header("⚙️ System Status")
    try:
        res = requests.get(f"{BACKEND_URL}/health", timeout=3)
        if res.status_code == 200:
            st.success("Backend: CONNECTED (Port 8000)")
        else:
            st.warning("Backend returned non-200 status")
    except Exception:
        st.error("Backend: OFFLINE (Using local fallback analysis if needed)")

    st.markdown("---")
    st.header("👥 Project Roles")
    st.markdown("""
    - **M1:** Lead / Architecture
    - **M2:** IPsec / strongSwan Lab
    - **M3:** Packet Analyst (Scapy/PCAP)
    - **M4:** Security Rules & Risk Engine
    - **M5:** FastAPI & SQLite Backend
    - **M6:** Streamlit UI & ML Anomalies
    """)
    st.markdown("---")
    st.markdown("⚠️ *VajraNet adheres to the Claims, Evidence, and Limitations principle.*")

# File Upload Section
st.header("📁 Upload Capture File")
uploaded_file = st.file_uploader("Upload an authorized PCAP or PCAPNG capture file", type=["pcap", "pcapng", "cap"])

if uploaded_file is not None:
    st.info(f"File uploaded: **{uploaded_file.name}** ({round(uploaded_file.size / 1024, 2)} KB)")

    if st.button("🚀 Analyze VPN Capture", type="primary"):
        with st.spinner("Analyzing packet capture and verifying security rules..."):
            try:
                # Call backend API
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
                response = requests.post(f"{BACKEND_URL}/analyze", files=files, timeout=60)

                if response.status_code == 200:
                    data = response.json()
                else:
                    st.error(f"Analysis failed: {response.text}")
                    data = None
            except Exception as e:
                st.warning(f"Backend API call failed ({e}). Running local analyzer fallback...")
                # Fallback to local import if backend is offline
                from analyzer.pcap_reader import read_pcap
                from analyzer.ike_analyzer import analyze_ike_packets
                from analyzer.esp_analyzer import analyze_esp_packets
                from analyzer.feature_extractor import extract_vpn_features
                from analyzer.timeline import build_sa_timeline
                from security.rules import evaluate_security_rules
                from security.risk_score import calculate_risk_score
                from ml.anomaly import detect_anomalies

                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp.write(uploaded_file.getvalue())
                    tmp_path = tmp.name

                pcap_data = read_pcap(tmp_path)
                ike_data = analyze_ike_packets(pcap_data["packets"])
                esp_data = analyze_esp_packets(pcap_data["packets"])
                features = extract_vpn_features(pcap_data, ike_data, esp_data)
                timeline = build_sa_timeline(ike_data["ike_events"])
                findings = evaluate_security_rules(ike_data, esp_data)
                risk = calculate_risk_score(findings)
                anomalies = detect_anomalies(features)

                data = {
                    "filename": uploaded_file.name,
                    "packet_count": pcap_data["total_packets"],
                    "duration": pcap_data["duration"],
                    "tunnel_info": {
                        "ike_version": ike_data.get("ike_version", "IKEv2"),
                        "endpoints": pcap_data.get("endpoints", []),
                        "spis": esp_data.get("spis", []),
                        "encryption_algorithm": ike_data.get("encryption", "Unknown"),
                        "integrity_algorithm": ike_data.get("integrity", "Unknown"),
                        "tunnel_status": "ACTIVE" if esp_data.get("packet_count", 0) > 0 else "INACTIVE"
                    },
                    "risk_score": risk["score"],
                    "risk_level": risk["level"],
                    "findings": findings,
                    "threat_matrix": risk["threat_matrix"],
                    "timeline": timeline,
                    "anomalies": anomalies,
                    "features": features
                }

        if data:
            st.success("✅ Analysis completed successfully!")

            # 1. Summary Cards
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Packets", f"{data['packet_count']:,}")
            col2.metric("Duration", f"{data['duration']} s")
            col3.metric("Risk Score", f"{data['risk_score']} / 100")

            level_colors = {
                "LOW": "🟢 LOW",
                "MEDIUM": "🟡 MEDIUM",
                "HIGH": "🟠 HIGH",
                "CRITICAL": "🔴 CRITICAL"
            }
            col4.metric("Risk Level", level_colors.get(data['risk_level'], data['risk_level']))

            st.divider()

            # 2. Tunnel Inventory
            st.subheader("🌐 Tunnel Inventory")
            t_info = data.get("tunnel_info", {})
            t_col1, t_col2, t_col3 = st.columns(3)
            t_col1.write(f"**Tunnel Status:** `{t_info.get('tunnel_status')}`")
            t_col1.write(f"**Protocol Version:** `{t_info.get('ike_version')}`")
            t_col2.write(f"**Encryption:** `{t_info.get('encryption_algorithm')}`")
            t_col2.write(f"**Integrity:** `{t_info.get('integrity_algorithm')}`")
            t_col3.write(f"**SPIs:** `{', '.join(t_info.get('spis', [])) if t_info.get('spis') else 'None'}`")
            t_col3.write(f"**Endpoints:** `{', '.join(t_info.get('endpoints', [])) if t_info.get('endpoints') else 'None'}`")

            st.divider()

            # 3. Threat Matrix & Findings
            st.subheader("🚨 Threat Matrix & Security Findings")
            findings = data.get("findings", [])
            if findings:
                df_findings = pd.DataFrame(data.get("threat_matrix", findings))
                st.dataframe(df_findings, use_container_width=True)
            else:
                st.success("🎉 No policy violations or security misconfigurations detected!")

            st.divider()

            # 4. SA Lifecycle Timeline
            st.subheader("⏱️ Security Association (SA) Timeline")
            timeline = data.get("timeline", [])
            if timeline:
                df_timeline = pd.DataFrame(timeline)
                st.dataframe(df_timeline[["timestamp", "event", "endpoints", "description"]], use_container_width=True)
            else:
                st.info("No IKE negotiation events recorded in this capture.")

            st.divider()

            # 5. Anomaly Findings
            st.subheader("🤖 Anomaly Detection (ML Isolation Forest)")
            anomalies = data.get("anomalies", [])
            if anomalies:
                for a in anomalies:
                    st.warning(f"**[{a.get('type')}]** ({a.get('severity')}): {a.get('description')}")
            else:
                st.success("No statistical traffic anomalies or flooding patterns detected.")

            st.divider()

            # 6. Report Export
            st.subheader("📄 Security Assessment Report")
            report_text = f"""# VajraNet Security Assessment Report
File: {data['filename']}
Packets: {data['packet_count']}
Duration: {data['duration']}s
Tunnel Status: {t_info.get('tunnel_status')}
Risk Score: {data['risk_score']} ({data['risk_level']})

## Security Findings
{json.dumps(findings, indent=2)}

## Threat Matrix
{json.dumps(data.get('threat_matrix', []), indent=2)}

## Anomalies
{json.dumps(anomalies, indent=2)}
"""
            st.download_button(
                label="📥 Download Security Assessment Report",
                data=report_text,
                file_name=f"vajranet_report_{data['filename']}.md",
                mime="text/markdown"
            )

else:
    st.info("👆 Please upload an IPsec PCAP file from the `pcaps/` directory to begin analysis.")
