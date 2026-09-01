# DiodeSentinel: Passive Unidirectional AI Cyber Threat Detection Pipeline

> **Enterprise / Defense-grade Real-Time Network Threat Intelligence for Hardware Data Diodes and Air-Gapped Monitoring Enclaves.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 1. Problem Context & Architectural Constraints

Critical infrastructure (energy grids, nuclear facilities, defense command networks, and financial settlement cores) enforce **one-way data diode enclaves** or passive optical taps to mirror production traffic.

The enclave has **no physical or protocol-level path back** into the protected network:
- **Zero Return-Path:** Cannot complete TCP handshakes, cannot send ICMP/SNMP probes, and cannot issue inline mitigation commands.
- **Zero Decryption:** Cannot decrypt TLS/QUIC payloads without exposing private keys in the enclave.
- **Strictly Streaming:** Must process traffic incrementally with bounded sub-10ms latency.

---

## 2. Threat Vector Detection Engine (6/6 Covered)

| Threat Class | Passive Ingestion Features | Algorithmic / ML Technique | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **a. Volumetric / Protocol DDoS** | Packet rate (pps), Bandwidth (bps), SYN-to-ACK ratio, Source IP Shannon Entropy $H(S)$. | Sliding Window Shannon Entropy + Flag Asymmetry | `T1498` (Network Denial of Service) |
| **b. Botnet C2 Beaconing** | Inter-Arrival Times (IAT), IAT variance $\sigma$, Coefficient of Variation $CV = \sigma/\mu$, Spectral Power Peak. | Inter-Arrival Time Statistics & Autocorrelation / FFT | `T1071.001` (Web Protocols) |
| **c. DGA & DNS Tunnelling** | Character Shannon entropy $H(D)$, Consonant-vowel ratio, Subdomain Length, Base64/Hex density. | Lexical Shannon Entropy & N-Gram Density Classifier | `T1568.002` (DGA) & `T1071.004` (DNS) |
| **d. Encrypted Malware** | TLS Client Hello metadata, JA3/JA3S fingerprint MD5 hashes, Sequence of Packet Lengths (SPLT). | Pre-indexed Threat Intelligence DB + SPLT Sequence Classifier | `T1573` (Encrypted Channel) |
| **e. Recon & Port Scanning** | Single-source fan-out degree (distinct destination IPs and Ports in window $\Delta t$). | Bipartite Graph Fan-Out Tracker & Scan Velocity Estimator | `T1046` (Network Service Discovery) |
| **f. Data Exfiltration** | Outbound-to-inbound byte ratio $\frac{\text{Bytes}_{\text{out}}}{\text{Bytes}_{\text{in}}}$, sustained upload burst velocity. | Flow Volume Asymmetry & Burst Outlier Engine | `T1048` (Exfiltration Over Alt Protocol) |

---

## 3. Quick Start & Execution

### 1. Launch the Official Streamlit Live Dashboard (Recommended in PDF)
```bash
python diode_sentinel/run_sentinel.py --streamlit
# or
streamlit run diode_sentinel/dashboard/streamlit_app.py
```
This launches the official **Streamlit Live Dashboard** with real-time threat detection, 1-click attack simulation buttons, and the **Cryptographic SHA-256 Hash-Chain Audit Ledger** verification widget.

### 2. Launch the Native Desktop Cyber Defense Application (PyQt6)
```bash
python diode_sentinel/run_sentinel.py
```
Opens the standalone Windows Desktop SOC window.

### 3. Launch in FastAPI Web Mode
```bash
python diode_sentinel/run_sentinel.py --web
```
Starts the FastAPI & WebSocket backend on `http://localhost:8000`.

---

## 4. Cryptographic SHA-256 Hash-Chain Audit Ledger

To preserve a clean forensic chain of custody in compliance with **Problem Statement ID 26145**, every security alert is cryptographically sealed into an append-only hash chain:

$$\text{Block}_{n}.\text{hash} = \text{SHA-256}\left(\text{Block}_{n-1}.\text{hash} + \text{Timestamp} + \text{Alert ID} + \text{Evidence Digest}\right)$$

- **Zero Evidence Tampering:** Any retroactive alteration, insertion, or deletion of alerts immediately invalidates the cryptographic hash chain.
- **Dual Storage:** Automatically persists to both SQLite (`sentinel_events.db`) and JSONL audit ledger (`forensic_audit_ledger.jsonl`).

### 2. Run Automated Test Suite
```bash
python -m unittest diode_sentinel/tests/test_detectors.py
```

### 3. Run High-Throughput Performance Benchmark
```bash
python diode_sentinel/tests/benchmark.py 50000
```

---

## 4. Standardized JSON Alert Schema

Every security alert emitted adheres to this schema:
```json
{
  "timestamp": "2026-08-23T10:35:12.102Z",
  "alert_id": "ALT-8F9210B4",
  "flow_id": "10.0.1.105:49210 -> 198.51.100.22:443 [TCP]",
  "threat_class": "BOTNET_C2_BEACONING",
  "subtype": "PERIODIC_HEARTBEAT_BEACON",
  "severity": "HIGH",
  "confidence_score": 0.94,
  "mitre_technique": "T1071.001 - Application Layer Protocol: Web Protocols",
  "summary": "Botnet C2 Beaconing to 198.51.100.22:443 every 3.0s (Jitter: ±0.03s, CV: 0.01)",
  "evidence": {
    "beacon_count": 6,
    "mean_interval_sec": 3.0,
    "jitter_std_sec": 0.03,
    "coefficient_of_variation": 0.01,
    "spectral_periodicity_score": 0.98,
    "target_c2_endpoint": "198.51.100.22:443",
    "detection_logic": "Flow exhibits tight inter-arrival periodicity (3.0s ± 0.03s, CV=0.01)"
  },
  "flow_snapshot": {
    "packet_count": 6,
    "byte_count": 1188,
    "duration_sec": 15.02,
    "pps": 0.4,
    "ja3_hash": null,
    "sni": null
  }
}
```

---

## 5. Live SOC Dashboard Features

- **Real-Time Telemetry:** Ingestion rates (Mbps & PPS), active 5-tuple flows in memory.
- **Threat Radar Chart:** Instant visualization across all 6 threat vectors.
- **1-Click Attack Injection Studio:** Trigger live attacks into the stream (SYN Flood, C2 Beacon, DNS Tunnel, DGA, Cobalt Strike JA3, Port Scan, Data Exfil).
- **Forensic Inspector Modal:** Click any alert to inspect quantitative mathematical features and explanation logic.
- **Offline PCAP Replay:** Drag & drop any `.pcap` capture file to replay through the diode pipeline.
- **JSON Alert Export:** One-click download for SOC integration or SIEM ingestion.
