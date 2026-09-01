"""
DiodeSentinel - Core Configuration & Threat Thresholds
Enterprise-grade Passive Unidirectional Threat Detection Pipeline
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PCAP_DIR = BASE_DIR / "pcaps"
LOGS_DIR = BASE_DIR / "logs"

for directory in [DATA_DIR, PCAP_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Server & Ingest Settings
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000
WEBSOCKET_BROADCAST_INTERVAL_MS = 100  # 10 Hz live metric updates
MAX_ALERTS_IN_MEMORY = 500
MAX_FLOWS_IN_MEMORY = 2000

# Pipeline Performance & Sliding Window
SLIDING_WINDOW_SEC = 10.0       # 10s sliding window for short-term anomaly tracking
LONG_WINDOW_SEC = 60.0          # 60s window for beaconing & exfiltration tracking
CLEANUP_INTERVAL_SEC = 15.0     # Expire inactive flows
MIN_PACKETS_FOR_INFERENCE = 3

# Threat Detection Thresholds
THRESHOLDS = {
    # 1. Volumetric / Protocol DDoS
    "ddos": {
        "min_pps_per_ip": 150.0,              # Packets/sec to trigger rate check
        "min_bps_per_ip": 1_000_000,          # 1 MB/s
        "syn_ack_ratio_threshold": 4.0,       # SYN to ACK imbalance
        "min_entropy_drop": 1.2,              # Shannon entropy drop (low entropy = concentrated attack)
        "udp_amplification_multiplier": 5.0   # Outbound response >> Inbound query
    },
    # 2. Botnet C2 Beaconing
    "c2_beacon": {
        "min_beacon_count": 4,                # Minimum periodic connections
        "max_jitter_cv": 0.15,                # Coefficient of variation (std/mean) < 15% indicates strict periodicity
        "min_interval_sec": 1.0,              # Minimum interval
        "max_interval_sec": 300.0,            # Maximum interval (5 min)
        "fft_periodicity_threshold": 0.70     # Spectral peak power score
    },
    # 3. DGA & DNS Tunnelling
    "dns_tunnel": {
        "shannon_entropy_threshold": 3.4,     # High character randomness in domain
        "subdomain_length_threshold": 24,     # Exceptionally long subdomain
        "consonant_ratio_threshold": 0.72,    # Unusually high consonant density
        "txt_record_query_ratio": 0.35,       # High percentage of TXT queries
        "hex_base64_density_threshold": 0.65  # Base64/Hex encoding ratio in subdomain
    },
    # 4. Encrypted Malware (TLS/QUIC)
    "tls_malware": {
        "enable_ja3_matching": True,
        "splt_packet_count": 15,              # Inspect first N packet lengths and directions
        "ml_confidence_threshold": 0.75
    },
    # 5. Reconnaissance & Port Scanning
    "port_scan": {
        "min_unique_ports_window": 12,        # Target ports per source in window
        "min_unique_ips_window": 8,           # Target IPs per source in window (sweep)
        "syn_only_ratio_threshold": 0.85,     # Percentage of SYN without data payload
        "scan_rate_per_sec": 5.0              # Probes/sec
    },
    # 6. Data Exfiltration
    "data_exfil": {
        "outbound_inbound_ratio": 8.0,        # Outbound bytes >> Inbound bytes
        "min_outbound_bytes": 50_000,         # Min 50 KB to consider exfiltration
        "upload_burst_velocity_bps": 50_000   # 50 KB/s sustained burst
    }
}

# MITRE ATT&CK Framework Mapping
MITRE_MAPPINGS = {
    "VOLUMETRIC_DDOS": {
        "technique_id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/"
    },
    "BOTNET_C2_BEACONING": {
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "DGA_DNS_TUNNEL": {
        "technique_id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control / Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1071/004/"
    },
    "ENCRYPTED_MALWARE": {
        "technique_id": "T1573",
        "name": "Encrypted Channel",
        "tactic": "Command and Control / Execution",
        "url": "https://attack.mitre.org/techniques/T1573/"
    },
    "PORT_SCAN_RECON": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "DATA_EXFILTRATION": {
        "technique_id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1048/"
    }
}
