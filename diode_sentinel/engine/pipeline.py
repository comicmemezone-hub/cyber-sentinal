"""
DiodeSentinel - Streaming Inference Pipeline & Alert Coordinator
Near Real-Time Multi-Head Threat Detection over Unidirectional IP Data Streams
"""

import time
import uuid
import datetime
from collections import deque
from typing import Dict, List, Any, Optional, Callable

from diode_sentinel.config import MAX_ALERTS_IN_MEMORY, MAX_FLOWS_IN_MEMORY, DATA_DIR
from diode_sentinel.engine.flow_aggregator import FlowAggregator, FlowRecord
from diode_sentinel.engine.diode_ingest import DiodePacket
from diode_sentinel.models.ddos_detector import DDoSDetector
from diode_sentinel.models.c2_detector import C2BeaconDetector
from diode_sentinel.models.dns_detector import DNSTunnelDetector
from diode_sentinel.models.tls_malware_detector import TLSMalwareDetector
from diode_sentinel.models.recon_detector import PortScanDetector
from diode_sentinel.models.exfil_detector import DataExfiltrationDetector
from diode_sentinel.blockchain.audit_ledger import HashChainLedger
from diode_sentinel.storage.sqlite_store import SQLiteStore


class ThreatPipeline:
    """Coordinates stream ingestion, feature extraction, multi-head model inference, and alert dispatch."""

    def __init__(self, auto_seed: bool = False):
        self.aggregator = FlowAggregator()
        
        # Dual-Store: SQLite Database + Cryptographic SHA-256 Hash-Chain Audit Ledger
        self.sqlite_store = SQLiteStore()
        ledger_path = str(DATA_DIR / "forensic_audit_ledger.jsonl")
        self.audit_ledger = HashChainLedger(ledger_file=ledger_path)
        
        # Instantiate 6 Threat Vector Detectors
        self.detectors = [
            DDoSDetector(),
            C2BeaconDetector(),
            DNSTunnelDetector(),
            TLSMalwareDetector(),
            PortScanDetector(),
            DataExfiltrationDetector()
        ]
        
        # In-memory Alert Store (FIFO with max capacity)
        self.alerts: deque = deque(maxlen=MAX_ALERTS_IN_MEMORY)
        self.alert_listeners: List[Callable[[Dict[str, Any]], None]] = []
        
        # Throttling dictionary: (flow_key, subtype) -> last_alert_timestamp
        self.last_alert_time: Dict[str, float] = {}
        self.alert_cooldown_sec = 2.5  # Prevent alert storm on continuous attack
        
        # Live Performance & Telemetry Tracking
        self.start_time = time.time()
        self.total_packets_processed = 0
        self.total_bytes_processed = 0
        self.total_flows_seen = 0
        
        # Sliding rate meters (computed over last 1-2 seconds)
        self._metric_window_start = time.time()
        self._metric_pkts_in_window = 0
        self._metric_bytes_in_window = 0
        self.current_pps = 0.0
        self.current_mbps = 0.0
        self.current_fps = 0.0  # Flows per second

        # Threat counts by category
        self.threat_counts = {
            "VOLUMETRIC_DDOS": 0,
            "BOTNET_C2_BEACONING": 0,
            "DGA_DNS_TUNNEL": 0,
            "ENCRYPTED_MALWARE": 0,
            "PORT_SCAN_RECON": 0,
            "DATA_EXFILTRATION": 0
        }

        if auto_seed:
            self.seed_initial_demo_state()

    def seed_initial_demo_state(self):
        """Seed realistic initial threat alerts and flow state for immediate dashboard visualization."""
        from diode_sentinel.simulator.attack_scenarios import AttackScenarios
        
        # Inject standard benign baseline flows
        for _ in range(120):
            pkt = AttackScenarios.generate_benign_packet()
            self.process_packet(pkt)

        # Inject initial threat scenarios so the dashboard has rich historical alerts
        initial_attacks = [
            AttackScenarios.generate_syn_flood(count=15),
            AttackScenarios.generate_c2_beacon(beacon_count=6),
            AttackScenarios.generate_dns_tunnel(count=6),
            AttackScenarios.generate_dga_queries(count=5),
            AttackScenarios.generate_tls_malware_session(),
            AttackScenarios.generate_port_scan(scan_type="vertical"),
            AttackScenarios.generate_data_exfiltration(volume_mb=2.0)
        ]
        
        for batch in initial_attacks:
            for pkt in batch:
                self.process_packet(pkt)

    def register_alert_listener(self, listener: Callable[[Dict[str, Any]], None]):
        """Register a callback for real-time WebSocket alert dispatch."""
        self.alert_listeners.append(listener)

    def process_packet(self, packet: DiodePacket) -> List[Dict[str, Any]]:
        """
        Ingest a packet from the unidirectional diode link, update flow state,
        and run inference across all threat models.
        """
        now = time.time()
        self.total_packets_processed += 1
        self.total_bytes_processed += packet.size
        self._metric_pkts_in_window += 1
        self._metric_bytes_in_window += packet.size

        # Ingest packet into flow state
        flow = self.aggregator.ingest_packet(
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            size=packet.size,
            timestamp=packet.timestamp,
            tcp_flags=packet.tcp_flags,
            dns_info=packet.dns_info,
            tls_info=packet.tls_info
        )
        
        # Run inference across all 6 threat detectors
        raised_alerts = []
        for detector in self.detectors:
            try:
                detection = detector.analyze(flow, self.aggregator)
                if detection:
                    alert = self._create_alert(flow, detection, now)
                    if alert:
                        raised_alerts.append(alert)
            except Exception as e:
                # Robust fault isolation per detector
                pass

        # Update sliding telemetry rates
        elapsed = now - self._metric_window_start
        if elapsed >= 1.0:
            self.current_pps = self._metric_pkts_in_window / elapsed
            self.current_mbps = (self._metric_bytes_in_window * 8) / (elapsed * 1_000_000.0)
            self.current_fps = len(self.aggregator.flows) / max(1.0, elapsed)
            self._metric_window_start = now
            self._metric_pkts_in_window = 0
            self._metric_bytes_in_window = 0

        return raised_alerts

    def _create_alert(self, flow: FlowRecord, detection: Dict[str, Any], current_time: float) -> Optional[Dict[str, Any]]:
        """Construct a standardized JSON alert record and enforce cooldown deduplication."""
        flow_key = flow.flow_key
        subtype = detection.get("subtype", "GENERAL")
        threat_class = detection.get("threat_class", "UNKNOWN")

        # Determine semantic throttle key:
        # - DDoS/Targets throttled per target host
        # - Recon/Scanners throttled per scanner IP
        # - Per-flow throttled per flow key
        if threat_class == "VOLUMETRIC_DDOS":
            throttle_key = f"DDOS::{flow.dst_ip}::{subtype}"
        elif threat_class == "PORT_SCAN_RECON":
            throttle_key = f"RECON::{flow.src_ip}::{subtype}"
        elif threat_class == "BOTNET_C2_BEACONING":
            throttle_key = f"C2::{flow.src_ip}->{flow.dst_ip}::{subtype}"
        elif threat_class == "DATA_EXFILTRATION":
            throttle_key = f"EXFIL::{flow.src_ip}->{flow.dst_ip}::{subtype}"
        else:
            throttle_key = f"{flow.flow_key}::{subtype}"
        
        # Check cooldown
        last_time = self.last_alert_time.get(throttle_key, 0.0)
        if (current_time - last_time) < self.alert_cooldown_sec:
            return None
            
        self.last_alert_time[throttle_key] = current_time
        
        alert_id = f"ALT-{str(uuid.uuid4())[:8].upper()}"
        
        # Increment threat stats
        if threat_class in self.threat_counts:
            self.threat_counts[threat_class] += 1
            
        alert_record = {
            "timestamp": datetime.datetime.fromtimestamp(current_time, datetime.timezone.utc).isoformat(),
            "alert_id": alert_id,
            "flow_id": flow_key,
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "threat_class": threat_class,
            "subtype": subtype,
            "severity": detection.get("severity", "MEDIUM"),
            "confidence_score": detection.get("confidence_score", 0.85),
            "mitre_technique": detection.get("mitre_technique", "N/A"),
            "summary": detection.get("summary", ""),
            "evidence": detection.get("evidence", {}),
            "flow_snapshot": {
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "duration_sec": round(flow.duration_sec, 2),
                "pps": round(flow.packets_per_sec, 1),
                "ja3_hash": flow.ja3_fingerprint,
                "sni": flow.sni
            }
        }
        
        self.alerts.appendleft(alert_record)

        # 1. Commit to SQLite Persistent Store
        try:
            self.sqlite_store.insert_alert(alert_record)
        except Exception:
            pass

        # 2. Cryptographically append to SHA-256 Hash-Chain Audit Ledger
        try:
            block = self.audit_ledger.append_alert(alert_record)
            alert_record["audit_block_hash"] = block.hash
            alert_record["audit_block_index"] = block.index
        except Exception:
            pass
        
        # Notify WebSocket listeners
        for listener in self.alert_listeners:
            try:
                listener(alert_record)
            except Exception:
                pass
                
        return alert_record

    def get_system_telemetry(self) -> Dict[str, Any]:
        """Produce comprehensive real-time system metrics for the dashboard."""
        uptime = max(1.0, time.time() - self.start_time)
        active_flows = self.aggregator.get_all_active_flows()
        
        recent_alerts_list = list(self.alerts)[:15]
        if not recent_alerts_list and self.sqlite_store:
            try:
                db_alerts = self.sqlite_store.get_recent_alerts(limit=15)
                recent_alerts_list = db_alerts
            except Exception:
                pass

        total_alerts_count = len(self.alerts) or len(recent_alerts_list)

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "uptime_sec": round(uptime, 1),
            "total_packets": self.total_packets_processed,
            "total_bytes": self.total_bytes_processed,
            "active_flows_count": len(active_flows),
            "current_pps": round(self.current_pps, 1),
            "current_mbps": round(self.current_mbps, 2),
            "current_fps": round(self.current_fps, 1),
            "total_alerts": total_alerts_count,
            "threat_counts": self.threat_counts,
            "recent_alerts": recent_alerts_list,
            "active_flows_sample": [f.to_dict() for f in active_flows[:20]]
        }

    def clear_all(self):
        """Reset internal states and alerts."""
        self.aggregator = FlowAggregator()
        self.alerts.clear()
        self.last_alert_time.clear()
        for k in self.threat_counts:
            self.threat_counts[k] = 0
