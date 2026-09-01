"""
DiodeSentinel - Threat Detector B: Botnet C2 Beaconing
Detects: Periodic Command & Control Heartbeats using Inter-Arrival Time (IAT) and Spectral Analysis
"""

from typing import Optional, Dict, Any
from diode_sentinel.config import THRESHOLDS, MITRE_MAPPINGS
from diode_sentinel.engine.flow_aggregator import FlowRecord, FlowAggregator
from diode_sentinel.engine.feature_extractor import FeatureExtractor


class C2BeaconDetector:
    """Detects periodic Botnet / C2 beaconing heartbeats passively from flow inter-arrival times."""

    def __init__(self):
        self.mitre = MITRE_MAPPINGS["BOTNET_C2_BEACONING"]
        self.thresholds = THRESHOLDS["c2_beacon"]

    def analyze(self, flow: FlowRecord, aggregator: FlowAggregator) -> Optional[Dict[str, Any]]:
        # Need minimum observation count to establish periodicity
        if len(flow.timestamps) < self.thresholds["min_beacon_count"]:
            return None

        # Calculate IAT statistics
        iat_stats = FeatureExtractor.calculate_iat_statistics(flow.timestamps)
        count = iat_stats["count"]
        mean_iat = iat_stats["mean_iat"]
        std_iat = iat_stats["std_iat"]
        cv = iat_stats["cv_iat"]  # Coefficient of Variation
        
        # Periodicity check: IAT must fall in realistic C2 range (1s - 300s)
        if not (self.thresholds["min_interval_sec"] <= mean_iat <= self.thresholds["max_interval_sec"]):
            return None

        # Spectral Periodicity / Autocorrelation Score
        periodicity_score = FeatureExtractor.calculate_spectral_periodicity(flow.timestamps)
        
        # Detection Condition: Low Jitter (CV < 0.15) OR Strong Spectral Peak (> 0.70)
        is_low_jitter = cv <= self.thresholds["max_jitter_cv"]
        is_spectral_periodic = periodicity_score >= self.thresholds["fft_periodicity_threshold"]

        if is_low_jitter or (count >= 5 and is_spectral_periodic):
            confidence = min(0.99, 0.75 + (0.20 * (1.0 - min(1.0, cv))) + (0.05 * min(count, 10) / 10.0))
            
            # Severity based on persistence
            severity = "HIGH" if count >= 8 else "MEDIUM"
            
            return {
                "threat_class": "BOTNET_C2_BEACONING",
                "subtype": "PERIODIC_HEARTBEAT_BEACON",
                "severity": severity,
                "confidence_score": round(float(confidence), 2),
                "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                "evidence": {
                    "beacon_count": count,
                    "mean_interval_sec": mean_iat,
                    "jitter_std_sec": std_iat,
                    "coefficient_of_variation": cv,
                    "spectral_periodicity_score": round(periodicity_score, 3),
                    "target_c2_endpoint": f"{flow.dst_ip}:{flow.dst_port}",
                    "detection_logic": f"Flow exhibits tight inter-arrival periodicity ({mean_iat}s ± {std_iat}s, CV={cv})"
                },
                "summary": f"Botnet C2 Beaconing to {flow.dst_ip}:{flow.dst_port} every {mean_iat}s (Jitter: ±{std_iat}s, CV: {cv})"
            }

        return None
