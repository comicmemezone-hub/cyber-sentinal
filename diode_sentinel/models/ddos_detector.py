"""
DiodeSentinel - Threat Detector A: Volumetric & Protocol DDoS
Detects: SYN Flood, UDP Reflection/Amplification, and Low-Entropy Spoofed Floods
"""

import time
from typing import Optional, Dict, Any, List
from diode_sentinel.config import THRESHOLDS, MITRE_MAPPINGS
from diode_sentinel.engine.flow_aggregator import FlowRecord, FlowAggregator
from diode_sentinel.engine.feature_extractor import FeatureExtractor


class DDoSDetector:
    """Detects Layer 4 volumetric and protocol denial-of-service floods."""

    def __init__(self):
        self.mitre = MITRE_MAPPINGS["VOLUMETRIC_DDOS"]
        self.thresholds = THRESHOLDS["ddos"]

    def analyze(self, flow: FlowRecord, aggregator: FlowAggregator) -> Optional[Dict[str, Any]]:
        """
        Analyze flow and global window statistics for DDoS patterns:
        1. Extreme Packet Rate (pps) or Byte Rate (bps)
        2. SYN Flood: High SYN-to-ACK imbalance (single-flow or destination-aggregate)
        3. UDP Reflection / Amplification
        4. Global Source-IP Entropy drop during volumetric bursts
        """
        pps = flow.packets_per_sec
        bps = flow.bytes_per_sec
        duration = flow.duration_sec
        dst_ip = flow.dst_ip

        # Check target destination aggregation (handles distributed/spoofed floods)
        dst_stats = aggregator.get_dst_stats(dst_ip)
        dst_syns = dst_stats["syns"]
        dst_acks = max(1, dst_stats["acks"])
        dst_pps = dst_stats["pps"]
        dst_syn_ratio = dst_syns / dst_acks

        # 1. Target-level or Flow-level SYN Flood Detection
        if dst_syns >= 20 and dst_syn_ratio >= self.thresholds["syn_ack_ratio_threshold"]:
            confidence = min(0.99, 0.75 + (dst_syn_ratio / 50.0) + (dst_pps / 1000.0))
            severity = "CRITICAL" if (dst_pps > 400 or dst_syns > 50) else "HIGH"
            
            return {
                "threat_class": "VOLUMETRIC_DDOS",
                "subtype": "TCP_SYN_FLOOD",
                "severity": severity,
                "confidence_score": round(float(confidence), 2),
                "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                "evidence": {
                    "syn_packets_observed": dst_syns,
                    "ack_packets_observed": dst_stats["acks"],
                    "syn_to_ack_ratio": round(dst_syn_ratio, 2),
                    "packet_rate_pps": round(dst_pps, 1),
                    "target_host": dst_ip,
                    "detection_logic": f"Target host {dst_ip} received {dst_syns} unacknowledged SYN packets (SYN/ACK Ratio: {round(dst_syn_ratio, 1)}:1)"
                },
                "summary": f"TCP SYN Flood targeting {dst_ip}:{flow.dst_port} at {round(dst_pps, 1)} pps ({dst_syns} SYNs, Ratio: {round(dst_syn_ratio, 1)}:1)"
            }

        # 2. Flow-level SYN Flood Detection (Single Source)
        if flow.protocol == "TCP" and flow.syn_count >= 15:
            ack_count = max(1, flow.ack_count)
            syn_ack_ratio = flow.syn_count / ack_count
            if syn_ack_ratio >= self.thresholds["syn_ack_ratio_threshold"]:
                confidence = min(0.99, 0.70 + (syn_ack_ratio / 50.0))
                return {
                    "threat_class": "VOLUMETRIC_DDOS",
                    "subtype": "TCP_SYN_FLOOD_SINGLE_SRC",
                    "severity": "HIGH",
                    "confidence_score": round(float(confidence), 2),
                    "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                    "evidence": {
                        "syn_packets_observed": flow.syn_count,
                        "ack_packets_observed": flow.ack_count,
                        "syn_to_ack_ratio": round(syn_ack_ratio, 2),
                        "packet_rate_pps": round(pps, 1),
                        "detection_logic": "Passive TCP flag asymmetry indicates unacknowledged connection flood"
                    },
                    "summary": f"TCP SYN Flood from {flow.src_ip} targeting {dst_ip}:{flow.dst_port}"
                }

        # 3. UDP Amplification / Volumetric Flood
        if flow.protocol == "UDP" and flow.packet_count >= 15 and (pps >= self.thresholds["min_pps_per_ip"] or bps >= self.thresholds["min_bps_per_ip"]):
            confidence = min(0.98, 0.75 + (pps / 1500.0))
            is_reflection = flow.src_port in [53, 123, 1900, 389, 11211] or flow.dst_port in [53, 123, 1900, 389, 11211]
            subtype = "UDP_AMPLIFICATION_REFLECTION" if is_reflection else "UDP_VOLUMETRIC_FLOOD"
            
            return {
                "threat_class": "VOLUMETRIC_DDOS",
                "subtype": subtype,
                "severity": "CRITICAL" if pps > 400 else "HIGH",
                "confidence_score": round(float(confidence), 2),
                "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                "evidence": {
                    "packet_rate_pps": round(pps, 1),
                    "bandwidth_mbps": round(bps * 8 / 1_000_000, 2),
                    "total_packets": flow.packet_count,
                    "total_bytes": flow.byte_count,
                    "target_service_port": flow.dst_port,
                    "detection_logic": "Passive UDP flow volume rate exceeding baseline capacity without handshake"
                },
                "summary": f"{subtype.replace('_', ' ')} against {flow.dst_ip}:{flow.dst_port} at {round(pps, 1)} pps ({round(bps*8/1_000_000, 2)} Mbps)"
            }

        # 3. Global Source IP Entropy Drop Anomaly
        if len(aggregator.active_src_ips_window) >= 100:
            sample_ips = aggregator.active_src_ips_window[-200:]
            entropy = FeatureExtractor.calculate_distribution_entropy(sample_ips)
            # Low entropy during high packet activity means traffic is monopolized by a single/few flood sources
            if entropy < self.thresholds["min_entropy_drop"] and pps >= 80.0:
                return {
                    "threat_class": "VOLUMETRIC_DDOS",
                    "subtype": "CONCENTRATED_SOURCE_FLOOD",
                    "severity": "HIGH",
                    "confidence_score": 0.88,
                    "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                    "evidence": {
                        "source_ip_entropy": round(entropy, 3),
                        "packets_per_sec": round(pps, 1),
                        "detection_logic": f"Source-IP Shannon entropy dropped to {round(entropy, 2)} bits (expected > 3.0 bits)"
                    },
                    "summary": f"Concentrated Volumetric Flood from {flow.src_ip} (Low Entropy: {round(entropy, 2)} bits)"
                }

        return None
