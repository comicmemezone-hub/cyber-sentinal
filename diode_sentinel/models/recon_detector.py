"""
DiodeSentinel - Threat Detector E: Reconnaissance & Port Scanning
Detects: Horizontal IP Sweeps, Vertical Port Scans, and SYN Stealth Probing
"""

from typing import Optional, Dict, Any
from diode_sentinel.config import THRESHOLDS, MITRE_MAPPINGS
from diode_sentinel.engine.flow_aggregator import FlowRecord, FlowAggregator


class PortScanDetector:
    """Detects active network reconnaissance and port sweeping passively via graph fan-out."""

    def __init__(self):
        self.mitre = MITRE_MAPPINGS["PORT_SCAN_RECON"]
        self.thresholds = THRESHOLDS["port_scan"]

    def analyze(self, flow: FlowRecord, aggregator: FlowAggregator) -> Optional[Dict[str, Any]]:
        src_ip = flow.src_ip
        fanout = aggregator.get_fanout_stats(src_ip)
        
        unique_ports = fanout["unique_ports_count"]
        unique_ips = fanout["unique_ips_count"]
        syn_count = fanout["total_syn_count"]
        pkt_count = fanout["total_packet_count"]

        # 1. Vertical Port Scan (Single Target IP, many ports probed)
        if unique_ports >= self.thresholds["min_unique_ports_window"]:
            confidence = min(0.99, 0.75 + (unique_ports / 100.0))
            severity = "HIGH" if unique_ports > 30 else "MEDIUM"
            
            return {
                "threat_class": "PORT_SCAN_RECON",
                "subtype": "VERTICAL_PORT_SCAN",
                "severity": severity,
                "confidence_score": round(float(confidence), 2),
                "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                "evidence": {
                    "source_scanner_ip": src_ip,
                    "unique_ports_scanned": unique_ports,
                    "total_syn_probes": syn_count,
                    "latest_probed_target": f"{flow.dst_ip}:{flow.dst_port}",
                    "detection_logic": f"Host {src_ip} initiated probes to {unique_ports} distinct ports within sliding window"
                },
                "summary": f"Vertical Port Scan from {src_ip}: {unique_ports} unique ports probed (Target: {flow.dst_ip})"
            }

        # 2. Horizontal Subnet Sweep (Single/Few ports, many target IPs)
        if unique_ips >= self.thresholds["min_unique_ips_window"]:
            confidence = min(0.98, 0.70 + (unique_ips / 50.0))
            severity = "HIGH" if unique_ips > 20 else "MEDIUM"
            
            return {
                "threat_class": "PORT_SCAN_RECON",
                "subtype": "HORIZONTAL_IP_SWEEP",
                "severity": severity,
                "confidence_score": round(float(confidence), 2),
                "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                "evidence": {
                    "source_scanner_ip": src_ip,
                    "unique_hosts_targeted": unique_ips,
                    "targeted_port": flow.dst_port,
                    "total_syn_probes": syn_count,
                    "detection_logic": f"Host {src_ip} swept across {unique_ips} distinct internal IPs on port {flow.dst_port}"
                },
                "summary": f"Horizontal Network Sweep from {src_ip}: {unique_ips} target hosts probed on port {flow.dst_port}"
            }

        return None
