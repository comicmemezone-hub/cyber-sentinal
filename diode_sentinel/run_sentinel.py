"""
DiodeSentinel - Single-Command Prototype Launcher
Starts the Unidirectional Ingest Stream, ML Detection Pipeline, and SOC Dashboard.
Supports direct PCAP file ingestion via CLI: python run_sentinel.py --pcap <path_to_file.pcap>
"""

import sys
import os
import webbrowser
import threading
import time
from pathlib import Path

# Add directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn
from diode_sentinel.config import SERVER_HOST, SERVER_PORT
from diode_sentinel.engine.diode_ingest import FastPcapParser
from diode_sentinel.engine.pipeline import ThreatPipeline
from diode_sentinel.server.app import pipeline as server_pipeline, app


def open_browser():
    time.sleep(1.2)
    url = f"http://localhost:{SERVER_PORT}"
    print(f"\n[+] Opening Cyber SOC Dashboard: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass


def print_banner():
    banner = f"""
    ========================================================================
       ____  _           _        ____             _   _            _ 
      |  _ \(_) ___   __| | ___  / ___|  ___ _ __ | |_(_)_ __   ___| |
      | | | | |/ _ \ / _` |/ _ \ \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
      | |_| | | (_) | (_| |  __/  ___) |  __/ | | | |_| | | | |  __/ |
      |____/|_|\___/ \__,_|\___| |____/ \___|_| |_|\__|_|_| |_|\___|_|
                                                                       
      Passive Unidirectional AI Cyber Threat Detection Pipeline (Diode)
    ========================================================================
      [+] Read-Only Ingest        : Active (Hardware Diode Zero-Return-Path)
      [+] Decryption Policy       : Zero Payload Decryption (JA3/JA4 & Metadata)
      [+] Threat Coverage (6/6)   :
          a. Volumetric / Protocol DDoS (SYN & UDP Reflection, Entropy Drop)
          b. Botnet C2 Beaconing (Periodicity & Low-Jitter IAT Spectral)
          c. DGA & DNS Tunnelling (Shannon Entropy & Base64/Hex Smuggling)
          d. Encrypted Malware (JA3 Fingerprinting & SPLT Classification)
          e. Recon & Port Scanning (Graph Fan-out & Horizontal/Vertical Sweep)
          f. Data Exfiltration (Asymmetric Byte Ratios & Upload Spikes)
      [+] SOC Live Dashboard      : http://localhost:{SERVER_PORT}
    ========================================================================
    """
    print(banner)


def ingest_pcap_cli(pcap_path: str):
    """Parse and ingest a local PCAP file through the passive diode pipeline."""
    path = Path(pcap_path)
    if not path.exists():
        print(f"[-] Error: File not found at '{pcap_path}'")
        sys.exit(1)

    print(f"\n[+] Ingesting Binary PCAP File: {path.resolve()}")
    print("[+] Reading raw Ethernet / IPv4 frames across passive data diode enclave...")
    
    count = 0
    t0 = time.time()
    for pkt in FastPcapParser.parse_pcap_file(str(path)):
        count += 1
        server_pipeline.process_packet(pkt)

    elapsed = time.time() - t0
    rate = count / max(elapsed, 0.001)

    print(f"[+] PCAP Ingestion Completed in {elapsed:.3f}s ({count} packets @ {rate:,.0f} pkts/s)")
    print(f"[+] Total Flows Tracked: {len(server_pipeline.aggregator.flows)}")
    print(f"[+] Total Threats Detected: {len(server_pipeline.alerts)}")
    
    for alert in server_pipeline.alerts:
        print(f"    -> [{alert.severity}] {alert.threat_type} from {alert.src_ip} (Score: {alert.risk_score}/100, Conf: {alert.confidence*100:.1f}%)")
    
    print("\n[+] Launching SOC Dashboard to inspect forensic evidence...")
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT, log_level="warning")


def free_port(port: int = 8000):
    """Gracefully terminates any existing background process occupying port 8000."""
    try:
        if sys.platform.startswith("win"):
            import subprocess
            cmd = f'powershell -Command "$conn = Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue; if ($conn) {{ $conn.OwningProcess | Select-Object -Unique | ForEach-Object {{ Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }} }}"'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=2.0)
            time.sleep(0.5)
    except Exception:
        pass


def main():
    print_banner()
    
    # Check CLI options
    if "--pcap" in sys.argv:
        pcap_idx = sys.argv.index("--pcap")
        if pcap_idx + 1 < len(sys.argv):
            pcap_file = sys.argv[pcap_idx + 1]
            free_port(SERVER_PORT)
            ingest_pcap_cli(pcap_file)
            return
        else:
            print("[-] Error: Please specify a PCAP path after --pcap.")
            sys.exit(1)
            
    elif "--streamlit" in sys.argv:
        print("[+] Launching Streamlit Dashboard...")
        script_path = str(Path(__file__).resolve().parent / "dashboard" / "streamlit_app.py")
        cmd = f'"{sys.executable}" -m streamlit run "{script_path}"'
        os.system(cmd)
    else:
        print("[+] Freeing port 8000 & Starting Cyber Sentinel SOC Server...")
        free_port(SERVER_PORT)
        print(f"[+] Server LIVE on http://localhost:{SERVER_PORT}")
        threading.Thread(target=open_browser, daemon=True).start()
        uvicorn.run(
            app,
            host=SERVER_HOST,
            port=SERVER_PORT,
            log_level="info"
        )


if __name__ == "__main__":
    main()
