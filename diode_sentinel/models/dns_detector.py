"""
DiodeSentinel - Threat Detector C: DGA Domains & DNS Tunnelling
Detects: Algorithmic Domain Generation (DGA) and Covert DNS Exfiltration/Tunneling
"""

import re
from typing import Optional, Dict, Any, List
from diode_sentinel.config import THRESHOLDS, MITRE_MAPPINGS
from diode_sentinel.engine.flow_aggregator import FlowRecord, FlowAggregator
from diode_sentinel.engine.feature_extractor import FeatureExtractor
from diode_sentinel.models.threat_db import DGA_KNOWN_PATTERNS


class DNSTunnelDetector:
    """Detects DGA (Domain Generation Algorithm) malware queries and DNS tunneling exfiltration."""

    def __init__(self):
        self.mitre = MITRE_MAPPINGS["DGA_DNS_TUNNEL"]
        self.thresholds = THRESHOLDS["dns_tunnel"]

    def analyze(self, flow: FlowRecord, aggregator: FlowAggregator) -> Optional[Dict[str, Any]]:
        if not flow.dns_queries:
            return None

        # Inspect latest DNS queries in this flow
        for dns_feat in reversed(flow.dns_queries[-10:]):
            domain = dns_feat.get("domain", "")
            subdomain = dns_feat.get("subdomain", "")
            entropy = dns_feat.get("entropy", 0.0)
            sub_len = dns_feat.get("subdomain_length", 0)
            consonant_ratio = dns_feat.get("consonant_ratio", 0.0)
            hex_ratio = dns_feat.get("hex_ratio", 0.0)
            base64_ratio = dns_feat.get("base64_ratio", 0.0)
            record_type = dns_feat.get("record_type", "A")
            is_txt_null = dns_feat.get("is_txt_or_null", False)
            
            # Skip known top legitimate short domains
            if any(domain.endswith(legit) for legit in ["google.com", "microsoft.com", "apple.com", "cloudflare.com", "amazon.com"]):
                continue

            # 1. DNS Tunneling Detection (Long Subdomain + High Entropy / Hex / Base64 / TXT)
            is_tunneling = (
                sub_len >= self.thresholds["subdomain_length_threshold"] and
                (entropy >= self.thresholds["shannon_entropy_threshold"] or hex_ratio >= 0.70 or base64_ratio >= 0.80)
            ) or (is_txt_null and sub_len >= 18 and entropy >= 3.2)

            if is_tunneling:
                confidence = min(0.99, 0.80 + (sub_len / 120.0) + (entropy / 10.0))
                severity = "CRITICAL" if (sub_len > 40 or is_txt_null) else "HIGH"
                
                return {
                    "threat_class": "DGA_DNS_TUNNEL",
                    "subtype": "DNS_COVERT_TUNNELING",
                    "severity": severity,
                    "confidence_score": round(float(confidence), 2),
                    "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                    "evidence": {
                        "queried_domain": domain,
                        "subdomain_payload": subdomain[:45] + ("..." if len(subdomain) > 45 else ""),
                        "subdomain_length": sub_len,
                        "shannon_entropy": entropy,
                        "hex_density": hex_ratio,
                        "base64_density": base64_ratio,
                        "record_type": record_type,
                        "detection_logic": f"Subdomain length ({sub_len} chars) & entropy ({entropy} bits) indicates encoded payload exfiltration via DNS"
                    },
                    "summary": f"DNS Tunneling / Data Smuggling via query '{subdomain[:30]}...{dns_feat.get('root_domain', '')}' ({record_type}, Entropy: {entropy})"
                }

            # 2. DGA Domain Detection (High Entropy + High Consonant density or Known Pattern)
            is_dga_pattern = any(bool(re.match(p, domain)) for p in DGA_KNOWN_PATTERNS)
            is_dga_statistical = (
                entropy >= self.thresholds["shannon_entropy_threshold"] and
                (consonant_ratio >= self.thresholds["consonant_ratio_threshold"] or dns_feat.get("max_consecutive_consonants", 0) >= 5) and
                sub_len >= 10
            )

            if is_dga_pattern or is_dga_statistical:
                confidence = min(0.96, 0.78 + (entropy / 12.0) + (consonant_ratio * 0.15))
                return {
                    "threat_class": "DGA_DNS_TUNNEL",
                    "subtype": "DGA_ALGORITHMIC_DOMAIN",
                    "severity": "HIGH",
                    "confidence_score": round(float(confidence), 2),
                    "mitre_technique": f"{self.mitre['technique_id']} - {self.mitre['name']}",
                    "evidence": {
                        "dga_domain": domain,
                        "shannon_entropy": entropy,
                        "consonant_ratio": consonant_ratio,
                        "max_consecutive_consonants": dns_feat.get("max_consecutive_consonants", 0),
                        "detection_logic": f"Domain exhibits pseudo-random DGA lexical properties (Entropy: {entropy}, Consonants: {round(consonant_ratio*100)}%)"
                    },
                    "summary": f"DGA Malicious Domain Query detected: '{domain}' (Entropy: {entropy}, Consonant: {round(consonant_ratio*100)}%)"
                }

        return None
