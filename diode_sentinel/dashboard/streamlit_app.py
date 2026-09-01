"""
DiodeSentinel - 4-Page Streamlit Cyber SOC Operations Platform
Problem Statement ID 26145 - Official 4-Page Reference Implementation
"""

import streamlit as st
import time
import json
import pandas as pd
from pathlib import Path
import sys

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from diode_sentinel.engine.pipeline import ThreatPipeline
from diode_sentinel.simulator.traffic_generator import TrafficGenerator
from diode_sentinel.config import MITRE_MAPPINGS

# Streamlit Page Config
st.set_page_config(
    page_title="DIODE SENTINEL // Cyber Threat Enclave",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State Singleton for Pipeline and Simulator
@st.cache_resource
def get_pipeline_and_simulator():
    pipeline = ThreatPipeline()
    simulator = TrafficGenerator(pipeline, base_pps=140.0)
    simulator.start()
    return pipeline, simulator

pipeline, simulator = get_pipeline_and_simulator()

# Custom Styling (White / Electric Blue / Midnight Black Theme)
st.markdown("""
<style>
    .main { background-color: #07090e; color: #f8fafc; }
    .stMetric { 
        background-color: #0d121d; 
        border: 1px solid #1e293b; 
        padding: 14px; 
        border-radius: 8px; 
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }
    .diode-badge {
        background-color: #064e3b;
        border: 1px solid #10b981;
        color: #ffffff;
        padding: 8px 16px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 12px;
        display: inline-block;
        margin-bottom: 12px;
        letter-spacing: 0.5px;
    }
    .stButton>button {
        background-color: #131b2e;
        color: #f8fafc;
        border: 1px solid #1e293b;
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    .stButton>button:hover {
        background-color: #004d66;
        border-color: #00f0ff;
        color: #ffffff;
    }
</style>
""", unsafe_allow_html=True)

# TOP HEADER
col_title, col_status = st.columns([2, 1])
with col_title:
    st.title("🛡️ DIODE SENTINEL")
    st.caption("PASSIVE UNIDIRECTIONAL THREAT DETECTION PLATFORM // PROBLEM ID 26145")

with col_status:
    st.markdown('<div class="diode-badge">🟢 HARDWARE DATA DIODE: RX ONLY (ZERO RETURN PATH)</div>', unsafe_allow_html=True)

# SIDEBAR: 4-Page Navigation & Attack Studio
st.sidebar.title("Navigation (4 Pages)")
selected_page = st.sidebar.radio(
    "Select Enclave View:",
    [
        "1. 🚨 Live Threat Stream & Attack Studio",
        "2. 🔬 Forensic Evidence & MITRE ATT&CK",
        "3. ⛓️ SHA-256 Hash-Chain Audit Ledger",
        "4. ⚡ PCAP Lab & Throughput Benchmark"
    ]
)

st.sidebar.divider()
st.sidebar.subheader("⚡ Attack Injection Studio")

if st.sidebar.button("💥 Volumetric SYN Flood (DDoS)", use_container_width=True):
    simulator.inject_attack("syn_flood")
    st.sidebar.success("Injected SYN Flood!")

if st.sidebar.button("📡 Cobalt Strike C2 Beacon", use_container_width=True):
    simulator.inject_attack("c2_beacon")
    st.sidebar.success("Injected C2 Periodic Beacon!")

if st.sidebar.button("🚇 Covert DNS Tunneling", use_container_width=True):
    simulator.inject_attack("dns_tunnel")
    st.sidebar.success("Injected DNS Base64 Tunnel!")

if st.sidebar.button("🌐 Algorithmic DGA Query", use_container_width=True):
    simulator.inject_attack("dga")
    st.sidebar.success("Injected DGA Domain Query!")

if st.sidebar.button("🔒 Emotet Malware TLS (JA3)", use_container_width=True):
    simulator.inject_attack("tls_malware")
    st.sidebar.success("Injected Malicious TLS Session!")

if st.sidebar.button("🔍 Recon & Vertical Port Scan", use_container_width=True):
    simulator.inject_attack("port_scan")
    st.sidebar.success("Injected Port Sweep!")

if st.sidebar.button("📤 Asymmetric Data Exfiltration", use_container_width=True):
    simulator.inject_attack("data_exfil")
    st.sidebar.success("Injected Data Exfil Burst!")

st.sidebar.divider()
if st.sidebar.button("🔄 Reset Alerts & Tables", use_container_width=True):
    pipeline.clear_all()
    st.sidebar.info("Pipeline reset.")

# Global Telemetry
telemetry = pipeline.get_system_telemetry()

# =========================================================================
# PAGE 1: LIVE THREAT STREAM & ATTACK OPERATIONS
# =========================================================================
if selected_page.startswith("1."):
    st.header("Page 1: Live Threat Operations & Ingestion Telemetry")
    
    # METRICS ROW
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Ingest Throughput", f"{telemetry['current_mbps']:.2f} Mbps", f"{telemetry['current_pps']:.0f} pkts/sec")
    m2.metric("Total Processed", f"{telemetry['total_packets']:,} pkts", f"{telemetry['total_bytes'] / (1024*1024):.1f} MB")
    m3.metric("Active Flows (10s)", f"{telemetry['active_flows_count']}", "Sliding 5-tuple table")
    m4.metric("Threat Alerts", f"{telemetry['total_alerts']}", f"{sum(1 for a in telemetry.get('recent_alerts', []) if a.get('severity') == 'CRITICAL')} Critical")

    st.divider()
    
    col_chart, col_alerts = st.columns([1, 1])
    with col_chart:
        st.subheader("Threat Category Distribution")
        threat_counts = telemetry.get("threat_counts", {})
        df_threats = pd.DataFrame({
            "Threat Class": list(threat_counts.keys()),
            "Detections": list(threat_counts.values())
        })
        st.bar_chart(df_threats.set_index("Threat Class"), color="#00f0ff")

    with col_alerts:
        st.subheader("Live Real-Time Alerts")
        alerts = telemetry.get("recent_alerts", [])
        if not alerts:
            st.info("Monitoring passive stream... Zero active threats.")
        else:
            for a in alerts[:8]:
                sev = a.get("severity", "MEDIUM")
                icon = "🔴" if sev == "CRITICAL" else ("🟡" if sev == "HIGH" else "🔵")
                st.write(f"{icon} **[{sev}]** `{a.get('threat_class')}` &rarr; {a.get('summary')}")

# =========================================================================
# PAGE 2: FORENSIC EVIDENCE & MITRE ATT&CK MATRIX
# =========================================================================
elif selected_page.startswith("2."):
    st.header("Page 2: Deep Forensic Inspector & MITRE ATT&CK Matrix")
    
    st.subheader("🛡️ MITRE ATT&CK Framework Mapping")
    mitre_cols = st.columns(3)
    idx = 0
    for t_class, info in MITRE_MAPPINGS.items():
        with mitre_cols[idx % 3]:
            st.markdown(f"""
            **{t_class.replace('_', ' ')}**  
            • Technique ID: `{info['technique_id']}`  
            • Technique Name: **{info['name']}**  
            • Tactic: *{info['tactic']}*  
            [MITRE Documentation ↗]({info['url']})
            """)
        idx += 1

    st.divider()
    st.subheader("🔬 Deep-Dive Forensic Alert Inspector")
    alerts = telemetry.get("recent_alerts", [])
    if not alerts:
        st.info("No alerts generated yet. Trigger an attack from the sidebar to inspect evidence.")
    else:
        for alert in alerts[:15]:
            sev = alert.get("severity", "MEDIUM")
            sev_icon = "🔴" if sev == "CRITICAL" else ("🟡" if sev == "HIGH" else "🔵")
            with st.expander(f"{sev_icon} [{sev}] {alert.get('threat_class')} ({alert.get('alert_id')}) — {alert.get('flow_id')}"):
                st.write(f"**Triage Summary:** {alert.get('summary')}")
                st.write(f"**Confidence Score:** `{int(alert.get('confidence_score', 0.85)*100)}%`")
                st.write(f"**MITRE Reference:** `{alert.get('mitre_technique')}`")
                st.write(f"**Cryptographic Hash:** `{alert.get('audit_block_hash', 'N/A')}`")
                st.write("**Extracted Statistical Indicators:**")
                st.json(alert.get("evidence", {}))

# =========================================================================
# PAGE 3: CRYPTOGRAPHIC SHA-256 HASH-CHAIN AUDIT LEDGER
# =========================================================================
elif selected_page.startswith("3."):
    st.header("Page 3: Cryptographic SHA-256 Hash-Chain Audit Ledger")
    st.caption("Immutable, append-only forensic audit trail ensuring zero evidence tampering.")

    # Integrity verification
    verification = pipeline.audit_ledger.verify_integrity()
    if verification.get("valid"):
        st.success(f"✅ HASH-CHAIN INTEGRITY VERIFIED: {verification.get('chain_length')} blocks cryptographically verified with zero tampering.")
    else:
        st.error(f"❌ INTEGRITY BREACH: {verification.get('error')}")

    # Display blocks table
    blocks_data = []
    for b in reversed(pipeline.audit_ledger.chain):
        blocks_data.append({
            "Block #": b.index,
            "Timestamp": time.strftime("%H:%M:%S", time.gmtime(b.timestamp)),
            "Alert ID": b.alert_id,
            "Threat Class": b.threat_class,
            "Current Block Hash (SHA-256)": b.hash,
            "Previous Block Hash": b.previous_hash
        })
    st.dataframe(pd.DataFrame(blocks_data), use_container_width=True)

# =========================================================================
# PAGE 4: PCAP LAB & THROUGHPUT BENCHMARK
# =========================================================================
elif selected_page.startswith("4."):
    st.header("Page 4: Offline PCAP Lab & High-Throughput Benchmarking")
    
    col_bench, col_flows = st.columns([1, 1])
    with col_bench:
        st.subheader("⚡ Live Performance Benchmark")
        bench_packets = st.slider("Benchmark Packet Volume", 5000, 50000, 20000, step=5000)
        
        if st.button(f"🚀 Run {bench_packets:,} Packet Benchmark", use_container_width=True):
            with st.spinner("Benchmarking sustained ingestion throughput..."):
                from diode_sentinel.simulator.attack_scenarios import AttackScenarios
                test_pkts = [AttackScenarios.generate_benign_packet() for _ in range(bench_packets)]
                bench_pipe = ThreatPipeline()
                
                t0 = time.perf_counter()
                for p in test_pkts:
                    bench_pipe.process_packet(p)
                t_elapsed = time.perf_counter() - t0
                
                pps = bench_packets / t_elapsed
                lat_us = (t_elapsed / bench_packets) * 1_000_000
                mbps = (bench_pipe.total_bytes_processed * 8) / (t_elapsed * 1_000_000)
                
                st.success("Benchmark Completed Successfully!")
                st.metric("Sustained Throughput", f"{pps:,.1f} pkts/sec", f"{mbps:.2f} Mbps")
                st.metric("Inference Latency", f"{lat_us:.2f} µs ({lat_us/1000:.4f} ms)", "Per-packet latency")

    with col_flows:
        st.subheader("Active 5-Tuple Network Flows")
        flows = telemetry.get("active_flows_sample", [])
        if flows:
            df_f = pd.DataFrame(flows)[["flow_key", "protocol", "packet_count", "byte_count", "duration_sec", "pps"]]
            st.dataframe(df_f, use_container_width=True)
        else:
            st.write("No active flows currently.")

# Auto-refresh loop
time.sleep(1.0)
st.rerun()
