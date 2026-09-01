"""
DiodeSentinel - Real-Time Diode Traffic Generator & Stream Simulator
Simulates a Continuous One-Way Ingest Feed with On-Demand Attack Injection
"""

import time
import threading
import queue
from typing import Optional, List, Dict, Any

from diode_sentinel.engine.pipeline import ThreatPipeline
from diode_sentinel.engine.diode_ingest import DiodePacket
from diode_sentinel.simulator.attack_scenarios import AttackScenarios


class TrafficGenerator:
    """Manages continuous baseline diode traffic and coordinates real-time attack injections."""

    def __init__(self, pipeline: ThreatPipeline, base_pps: float = 120.0):
        self.pipeline = pipeline
        self.base_pps = base_pps
        self.is_running = False
        
        self._thread: Optional[threading.Thread] = None
        self._injection_queue: queue.Queue = queue.Queue()
        self.total_injections = 0

    def start(self):
        """Start the background simulated diode stream."""
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop background generation."""
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def inject_attack(self, attack_name: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Queue a specific attack scenario to inject into the live diode stream."""
        params = params or {}
        self.total_injections += 1
        
        pkts: List[DiodePacket] = []
        name_lower = attack_name.lower()
        
        if "syn_flood" in name_lower or "ddos" in name_lower:
            pkts = AttackScenarios.generate_syn_flood(
                target_ip=params.get("target_ip", "10.0.1.50"),
                count=params.get("count", 60)
            )
        elif "udp_reflection" in name_lower:
            pkts = AttackScenarios.generate_udp_reflection(
                target_ip=params.get("target_ip", "10.0.1.50"),
                count=params.get("count", 40)
            )
        elif "c2_beacon" in name_lower or "botnet" in name_lower:
            pkts = AttackScenarios.generate_c2_beacon(
                bot_ip=params.get("bot_ip", "10.0.1.105"),
                c2_ip=params.get("c2_ip", "198.51.100.22"),
                interval_sec=params.get("interval_sec", 3.0),
                beacon_count=params.get("count", 6)
            )
        elif "dns_tunnel" in name_lower:
            pkts = AttackScenarios.generate_dns_tunnel(
                source_ip=params.get("source_ip", "10.0.1.77"),
                count=params.get("count", 6)
            )
        elif "dga" in name_lower:
            pkts = AttackScenarios.generate_dga_queries(
                source_ip=params.get("source_ip", "10.0.1.77"),
                count=params.get("count", 6)
            )
        elif "tls_malware" in name_lower or "cobalt" in name_lower or "encrypted" in name_lower:
            family = params.get("family", "Cobalt Strike")
            pkts = AttackScenarios.generate_tls_malware_session(
                source_ip=params.get("source_ip", "10.0.1.18"),
                c2_ip=params.get("c2_ip", "203.0.113.89"),
                malware_family=family
            )
        elif "port_scan" in name_lower or "recon" in name_lower:
            scan_type = params.get("scan_type", "vertical")
            pkts = AttackScenarios.generate_port_scan(
                scanner_ip=params.get("scanner_ip", "10.0.1.99"),
                target_ip=params.get("target_ip", "10.0.1.200"),
                scan_type=scan_type
            )
        elif "data_exfil" in name_lower or "exfil" in name_lower:
            pkts = AttackScenarios.generate_data_exfiltration(
                source_ip=params.get("source_ip", "10.0.1.44"),
                dropzone_ip=params.get("dropzone_ip", "185.220.101.5"),
                volume_mb=params.get("volume_mb", 3.5)
            )
        else:
            # Fallback to random attack
            pkts = AttackScenarios.generate_syn_flood()

        self._injection_queue.put(pkts)
        return f"Injected {len(pkts)} packets for scenario: {attack_name}"

    def _run_loop(self):
        """Streaming loop simulating unidirectional continuous traffic."""
        sleep_interval = 1.0 / max(10.0, self.base_pps)
        
        while self.is_running:
            # 1. Process any pending injected attack packets first
            while not self._injection_queue.empty():
                try:
                    attack_batch = self._injection_queue.get_nowait()
                    for pkt in attack_batch:
                        self.pipeline.process_packet(pkt)
                except Exception:
                    break

            # 2. Generate regular benign enterprise background packet
            benign_pkt = AttackScenarios.generate_benign_packet()
            self.pipeline.process_packet(benign_pkt)

            time.sleep(sleep_interval)
