# VajraNet AI — IPsec VPN Security Analyzer

VajraNet AI is an evidence-based VPN security analyzer designed to inspect authorized PCAP captures and VPN configurations, evaluate security policies (PFS, replay protection, cryptographic suites, SA lifetime), detect anomalies, and generate actionable remediation reports without breaking payload encryption.

---

## 👥 6-Member Team Roles & Responsibilities

| Member | Role | Primary Responsibility |
|---|---|---|
| **M1** | Lead / Architect | System architecture, Git workflow, integration, and interfaces |
| **M2** | IPsec Engineer | strongSwan lab, IKEv2/ESP protocol verification, test traffic generation |
| **M3** | Packet Analyst | Wireshark/tcpdump captures, Scapy PCAP parsing, header extraction |
| **M4** | Security Engineer | Security rules, policy verification, risk scoring, threat matrix |
| **M5** | Backend Engineer | FastAPI REST APIs, SQLite database schema, data pipeline |
| **M6** | Dashboard / ML | Streamlit user interface, timeline visualizations, anomaly detection |

---

## 🏗️ Architecture & Data Flow

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

---

## 📁 Repository Structure

```text
vajranet-ai/
│
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
│
├── backend/
│   ├── main.py
│   ├── api/
│   └── database/
│
├── analyzer/
│   ├── pcap_reader.py
│   ├── ike_analyzer.py
│   ├── esp_analyzer.py
│   ├── feature_extractor.py
│   └── timeline.py
│
├── security/
│   ├── rules.py
│   ├── risk_score.py
│   └── policy.yaml
│
├── ml/
│   ├── features.py
│   ├── train.py
│   └── anomaly.py
│
├── dashboard/
│   └── app.py
│
├── pcaps/
│   ├── normal/
│   ├── weak/
│   └── anomaly/
│
├── reports/
│
├── tests/
│
└── docs/
    ├── architecture.md
    ├── ipsec.md
    ├── security.md
    ├── privacy.md
    ├── testing.md
    ├── threat-model.md
    └── CLAIMS.md
```

---

## 🚀 Quick Start

### 1. Local Setup

```bash
# Clone the repository
git clone https://github.com/propirate99/VPN-Tester.git
cd VPN-Tester

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Backend (FastAPI)

```bash
uvicorn backend.main:app --reload --port 8000
```
API Documentation will be available at: `http://localhost:8000/docs`

### 3. Run Dashboard (Streamlit)

```bash
streamlit run dashboard/app.py --server.port 8501
```
Dashboard UI will be available at: `http://localhost:8501`

### 4. Run with Docker Compose

```bash
docker compose up --build
```

---

## 🧪 Testing

Run automated tests using pytest:

```bash
pytest tests/
```

---

## 📜 Ethical & Compliance Notice

VajraNet AI inspects only authorized, controlled captures. It operates on packet headers, metadata, and configuration policies, strictly adhering to privacy by **not decrypting payload content**. Every security and AI assertion follows the **Claim, Evidence, and Limitation** model documented in `docs/CLAIMS.md`.
