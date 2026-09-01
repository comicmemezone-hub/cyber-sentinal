# 🛡️ Cyber Sentinel: Passive Threat Detection in Unidirectional IP Traffic
> **Problem Statement ID:** 26145  
> **Theme:** Cybersecurity & Defense Enclave Monitoring  
> **Core Principle:** `PACKETS` $\longrightarrow$ `FLOWS` $\longrightarrow$ `FEATURES` $\longrightarrow$ `DETECTION` $\longrightarrow$ `RISK SCORE` $\longrightarrow$ `ALERT` $\longrightarrow$ `DATABASE` $\longrightarrow$ `LIVE DASHBOARD`

---

## 📌 1. Project Overview

**Cyber Sentinel** is a defense-grade network security monitoring platform engineered for **air-gapped and unidirectional hardware data diode enclaves**. 

Operating under a strict **Zero-Return-Path** constraint with **zero payload decryption**, it passively ingests network frames, reconstructs 5-tuple flow sessions, extracts non-invasive statistical features, and detects sophisticated cyber threats using a hybrid ensemble of machine learning and statistical models.

---

## 🗺️ 2. Enclave Architecture (PDF Page 31)

```
PCAP / FLOW STREAM ──► READ-ONLY DIODE INGEST ──► 5-TUPLE AGGREGATOR ──► FEATURE EXTRACTION
                                                                                 │
 ┌───────────────────────────────────────────────────────────────────────────────┘
 ▼
┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────────┐
│   Lane 1: Rules &    │      │ Lane 2: Unsupervised │      │   Lane 3: Supervised     │
│   Rate Statistics    │      │  Anomaly & Spectral  │      │    Machine Learning      │
│  (DDoS & Port Scan)  │      │  (C2 Beacon & Exfil) │      │  (DGA, DNS & TLS JA3)    │
└──────────────────────┘      └──────────────────────┘      └──────────────────────────┘
           │                             │                               │
           └─────────────────────────────┼───────────────────────────────┘
                                         ▼
                      THREAT SCORING ENGINE (0 - 100)
                                         │
                   ┌─────────────────────┴─────────────────────┐
                   ▼                                           ▼
       SQLITE PERSISTENT STORE                   SHA-256 HASH-CHAIN LEDGER
                   │                                           │
                   └─────────────────────┬─────────────────────┘
                                         ▼
                         REAL-TIME WEBSOCKET / SOC DASHBOARD
```

---

## 🔬 3. Multi-Head Detection Engines

| # | Threat Vector | Detection Technique & Mathematical Rationale | MITRE ATT&CK |
|---|---|---|---|
| 1 | **Volumetric DDoS / SYN Flood** | Packet velocity surge & SYN-to-ACK flag asymmetry ratio ($> 95\%$) | **T1498** |
| 2 | **Botnet C2 Beaconing** | Fast Fourier Transform (FFT) spectral power & IAT Gaussian jitter collapse ($CV < 0.15$) | **T1071.004** |
| 3 | **DNS Tunneling & DGA Domains** | Shannon Entropy $H(X) = -\sum p(x)\log_2 p(x) > 3.40$ & Base64 smuggling | **T1568 / T1071** |
| 4 | **Encrypted TLS Malware** | Zero-decryption JA3/JA4 MD5 fingerprinting & SPLT sequence analysis | **T1573** |
| 5 | **Port Scan Reconnaissance** | Bipartite graph fan-out tracker & vertical/horizontal port sweeps | **T1046** |
| 6 | **Data Exfiltration** | Outbound/Inbound volume asymmetry & upload velocity spikes | **T1048** |
| 7 | **Zero-Day Anomaly Lane** | Isolation Forest unsupervised outlier isolation | **Enterprise Anomaly** |

---

## 📁 4. Package Directory Structure

```
hackathon/
├── README.md                  # Complete documentation and judge demo guide
├── requirements.txt           # Python dependencies
├── run.py                     # Root single-command launcher
│
├── datasets/                  # 8 Real Authentic Benchmark .pcap captures
│   ├── benign/
│   │   └── normal_traffic.pcap
│   └── attacks/
│       ├── ddos.pcap
│       ├── beacon.pcap
│       ├── dns_tunnel.pcap
│       ├── encrypted_malware.pcap
│       ├── scan.pcap
│       ├── exfiltration.pcap
│       └── dga.pcap
│
├── diode_sentinel/            # Core Engine Package
│   ├── engine/                # PCAP parser, 5-tuple aggregator, live sniffer, feature extractor
│   ├── models/                # 7 AI/ML & statistical detection models
│   ├── storage/               # SQLite persistent store (sentinel_events.db)
│   ├── blockchain/            # Tamper-evident SHA-256 Hash-Chain Audit Ledger
│   ├── server/                # FastAPI backend & 10 Hz WebSocket engine
│   ├── dashboard/             # 7-page dark cyber theme UI (HTML, CSS, JS, Streamlit)
│   └── tests/                 # Automated test suite (12/12 passing)
│
└── docker/                    # Docker Compose One-Way Data Diode Enclave
    ├── Dockerfile
    ├── docker-compose.yml
    ├── entrypoint.sh
    └── traffic_source_replay.py
```

---

## 🚀 5. Quickstart & How to Run

### Method 1: Web SOC Dashboard (Single Command)
```powershell
cd d:\YT-Dowloader\hackathon
python run.py --web
```
*Open **`http://localhost:8000`** in your browser.*

---

### Method 2: Direct PCAP Ingestion
```powershell
# Replay any .pcap file from your drive:
python run.py --pcap "datasets/attacks/ddos.pcap"
```

---

### Method 3: Run Automated Test Suite
```powershell
python run.py --test
```
*(Runs all 12 unit and integration tests — 100% PASS)*

---

### Method 4: Multi-Container Docker Diode Enclave
```bash
cd d:\YT-Dowloader\hackathon\docker
docker compose up --build
```

---

## 🎬 6. 4-Minute Hackathon Judge Demo Script

| Demo Time | Action | What Judges See |
| :--- | :--- | :--- |
| **0:00 - 0:30** | Open `http://localhost:8000` | Clean passive SOC dashboard running in read-only diode mode. |
| **0:30 - 1:00** | Page 2 $\rightarrow$ Replay `normal_traffic.pcap` | Baseline benign flows processed; 0 threat alerts raised. |
| **1:00 - 1:45** | Page 2 $\rightarrow$ Replay `ddos.pcap` | **🚨 CRITICAL Alert**: SYN-to-ACK asymmetry ratio & flow velocity spike. |
| **1:45 - 2:30** | Page 2 $\rightarrow$ Replay `dns_tunnel.pcap` | **🚨 HIGH Alert**: Shannon entropy collapse $H(D) = 3.92$ & Base64 smuggling. |
| **2:30 - 3:00** | Page 2 $\rightarrow$ Replay `encrypted_malware.pcap` | **🚨 CRITICAL Alert**: Cobalt Strike JA3 MD5 match without payload decryption. |
| **3:00 - 3:30** | Page 3 $\rightarrow$ Click **"Inspect"** on an alert | **Threat Card Modal ($0 - 100$)** with feature contribution evidence. |
| **3:30 - 4:00** | Page 7 $\rightarrow$ Click **"Verify Chain"** | Cryptographic proof of the **SHA-256 Hash-Chain Audit Ledger**. |

---

## ⚖️ 7. Problem Statement 26145 Compliance Checklist

- [x] **Passive Ingestion Only:** Read-only optical/diode tap.
- [x] **Zero Return Path:** Egress traffic to production network dropped.
- [x] **Zero Payload Decryption:** Metadata, JA3 hashes, and timing features only.
- [x] **No Active Probing:** No TCP handshakes or ICMP pings initiated.
- [x] **Multi-Vector Detection:** DDoS, C2 Beaconing, DNS Tunnels, DGA, Malware, Scans, Exfil.
- [x] **Tamper-Evident Forensic Audit:** SHA-256 cryptographic hash chaining.
- [x] **Single Programming Language:** Pure Python 3.11+.
