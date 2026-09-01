"""
DiodeSentinel - Threat Detector F: Data Exfiltration
Detects: Asymmetric Flow Anomalies, Massive Upload Bursts, and Covert High-Volume Transfers
"""

from typing import Optional, Dict, Any
from diode_sentinel.config import THRESHOLDS, MITRE_MAPPINGS
from diode_sentinel.engine.flow_aggregator import FlowRecord, FlowAggregator


class DataExfiltrationDetector:
    """Detects unauthorized bulk data egress and asymmetric outbound flow spikes passively."""

    def __init__(self):
        self.mitre = MITRE_MAPPINGS["DATA_EXFILTRATION"]
        self.thresholds = THRESHOLDS["data_exfil"]

    def analyze(self, flow: FlowRecord, aggregator: FlowAggregator) -> Optional[Dict[str, Any]]:
        # Only inspect flows with meaningful outbound byte volume
        if flow.outbound_bytes < self.thresholds["min_outbound_bytes"]:
            return None

        byte_ratio = flow.byte_ratio_out_to_in
        outbound_mb = flow.outbound_bytes / (1024 * 1024)
        bps = flow.bytes_per_sec
        duration = flow.duration_sec

        # Exfiltration condition: Heavy outbound upload with stark asymmetry
        is_asymmetric_burst = (
            byte_ratio >= self.thresholds["outbound_inbound_ratio"] and
            (bps >= self.thresholds["upload_burst_velocity_bps"] or flow.outbound_bytes >= self.thresholds["min_outbound_bytes"])
        )

        if is_asymmetric_burst:
            confidence = min(0.98, 0.75 + min(0.20, outbound_mb / 5.0))
            severity = "CRITICAL" if outbound_mb > 5.0 else "HIGH"

            return {
                "threat_class": "DATA_EXFILTRATION",
                "subtype": "HIGH_VOLUME_ASYMMETRIC_EGRESS",
                "severity": severity,
                "confidence_score": round(float(confidence), 2),
                "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                "evidence": {
                    "outbound_bytes_mb": round(outbound_mb, 3),
                    "inbound_bytes_kb": round(flow.inbound_bytes / 1024, 2),
                    "outbound_inbound_ratio": round(byte_ratio, 1),
                    "upload_rate_mbps": round(bps * 8 / 1_000_000, 2),
                    "duration_sec": round(duration, 2),
                    "destination_endpoint": f"{flow.dst_ip}:{flow.dst_port}",
                    "detection_logic": f"Asymmetric egress ratio ({round(byte_ratio, 1)}:1) with sustained upload volume ({round(outbound_mb, 3)} MB)"
                },
                "summary": f"Data Exfiltration Alert: {round(outbound_mb, 3)} MB uploaded to {flow.dst_ip}:{flow.dst_port} (Out/In Ratio: {round(byte_ratio, 1)}:1)"
            }

        return None
