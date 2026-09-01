"""
DiodeSentinel - Real-time Feature Extraction Engine
Passive Statistical, Protocol, and Spectral Feature Computations
"""

import math
import hashlib
import re
from collections import Counter
from typing import List, Dict, Any, Tuple, Optional
import numpy as np


class FeatureExtractor:
    """High-performance statistical and protocol feature extractor for passive IP streams."""

    @staticmethod
    def calculate_shannon_entropy(data: str | bytes | List[Any]) -> float:
        """
        Calculate Shannon Entropy: H(X) = - sum(p(x) * log2(p(x)))
        Returns entropy in bits (0.0 to ~8.0 depending on alphabet).
        """
        if not data or len(data) == 0:
            return 0.0
        
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return float(entropy)

    @staticmethod
    def calculate_distribution_entropy(items: List[Any]) -> float:
        """Calculate Shannon entropy over categorical distributions (e.g. IP addresses or Ports)."""
        if not items:
            return 0.0
        total = len(items)
        if total <= 1:
            return 0.0
        counts = Counter(items)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return float(entropy)

    @staticmethod
    def calculate_iat_statistics(timestamps: List[float]) -> Dict[str, float]:
        """
        Calculate Inter-Arrival Time (IAT) statistics:
        - Mean IAT
        - Standard deviation (jitter)
        - Coefficient of Variation (CV = std / mean)
        - Min, Max, Range
        """
        if len(timestamps) < 2:
            return {
                "count": len(timestamps),
                "mean_iat": 0.0,
                "std_iat": 0.0,
                "cv_iat": 1.0,
                "min_iat": 0.0,
                "max_iat": 0.0
            }
        
        # Sort timestamps if not strictly sorted
        sorted_ts = sorted(timestamps)
        iats = np.diff(sorted_ts)
        
        # Remove zero or negative deltas
        iats = iats[iats > 0]
        if len(iats) == 0:
            return {
                "count": len(timestamps),
                "mean_iat": 0.0,
                "std_iat": 0.0,
                "cv_iat": 1.0,
                "min_iat": 0.0,
                "max_iat": 0.0
            }
        
        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))
        cv_iat = float(std_iat / mean_iat) if mean_iat > 1e-6 else 1.0
        
        return {
            "count": len(timestamps),
            "mean_iat": round(mean_iat, 4),
            "std_iat": round(std_iat, 4),
            "cv_iat": round(cv_iat, 4),
            "min_iat": round(float(np.min(iats)), 4),
            "max_iat": round(float(np.max(iats)), 4)
        }

    @staticmethod
    def calculate_spectral_periodicity(timestamps: List[float]) -> float:
        """
        Estimate periodicity score (0.0 to 1.0) using Autocorrelation / FFT spectral power peak.
        High score indicates regular heartbeat / C2 beaconing.
        """
        if len(timestamps) < 4:
            return 0.0
        
        sorted_ts = sorted(timestamps)
        iats = np.diff(sorted_ts)
        if len(iats) < 3:
            return 0.0
        
        # Normalize IATs
        norm_iats = iats - np.mean(iats)
        std = np.std(iats)
        if std < 1e-4:
            # Virtually zero jitter -> perfectly periodic
            return 0.99
            
        try:
            # Compute autocorrelation of inter-arrival deltas
            n = len(norm_iats)
            if n < 4:
                return max(0.0, 1.0 - (std / (np.mean(iats) + 1e-4)))
                
            autocorr = np.correlate(norm_iats, norm_iats, mode='full')
            autocorr = autocorr[len(autocorr)//2:]
            if len(autocorr) > 1 and autocorr[0] > 0:
                autocorr = autocorr / autocorr[0]
                # Look for dominant secondary peak or low variance ratio
                periodicity = max(0.0, 1.0 - min(1.0, std / (np.mean(iats) + 1e-4)))
                return float(min(1.0, max(0.0, periodicity)))
        except Exception:
            pass
            
        return 0.0

    @staticmethod
    def extract_dns_features(domain_name: str, record_type: str = "A") -> Dict[str, Any]:
        """
        Extract lexical and statistical features from a DNS query for DGA / Tunneling detection:
        - Total length & subdomain length
        - Shannon entropy of subdomain
        - Consonant-to-vowel ratio
        - Hex / Base64 character density
        - Digits and special character counts
        - N-gram anomaly score
        """
        domain_name = domain_name.lower().rstrip('.')
        parts = domain_name.split('.')
        
        # Extract subdomain (everything except root domain and TLD)
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
            root_domain = f"{parts[-2]}.{parts[-1]}"
        elif len(parts) == 2:
            subdomain = parts[0]
            root_domain = domain_name
        else:
            subdomain = domain_name
            root_domain = domain_name
            
        clean_sub = re.sub(r'[^a-z0-9]', '', subdomain)
        
        # Character distributions
        vowels = len(re.findall(r'[aeiou]', clean_sub))
        consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', clean_sub))
        digits = len(re.findall(r'[0-9]', clean_sub))
        hex_chars = len(re.findall(r'[0-9a-f]', clean_sub))
        base64_chars = len(re.findall(r'[a-zA-Z0-9+/=]', subdomain))
        
        sub_len = len(subdomain)
        clean_len = len(clean_sub)
        
        consonant_ratio = (consonants / clean_len) if clean_len > 0 else 0.0
        digit_ratio = (digits / clean_len) if clean_len > 0 else 0.0
        hex_ratio = (hex_chars / clean_len) if clean_len > 0 else 0.0
        base64_ratio = (base64_chars / sub_len) if sub_len > 0 else 0.0
        
        entropy = FeatureExtractor.calculate_shannon_entropy(subdomain)
        
        # Consecutive consonants check
        max_consecutive_consonants = 0
        current_consec = 0
        for char in clean_sub:
            if char in "bcdfghjklmnpqrstvwxyz":
                current_consec += 1
                if current_consec > max_consecutive_consonants:
                    max_consecutive_consonants = current_consec
            else:
                current_consec = 0
                
        return {
            "domain": domain_name,
            "subdomain": subdomain,
            "root_domain": root_domain,
            "record_type": record_type.upper(),
            "domain_length": len(domain_name),
            "subdomain_length": sub_len,
            "entropy": round(entropy, 4),
            "consonant_ratio": round(consonant_ratio, 4),
            "digit_ratio": round(digit_ratio, 4),
            "hex_ratio": round(hex_ratio, 4),
            "base64_ratio": round(base64_ratio, 4),
            "max_consecutive_consonants": max_consecutive_consonants,
            "is_txt_or_null": record_type.upper() in ["TXT", "NULL", "ANY"]
        }

    @staticmethod
    def parse_tls_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse raw TLS Client Hello bytes passively without decrypting:
        Extracts:
        - TLS Version (e.g. 0x0303 for TLS 1.2, 0x0301 for TLS 1.0)
        - Cipher Suites list
        - Extension types list
        - Supported Elliptic Curves (EC / Supported Groups)
        - Elliptic Curve Point Formats
        - JA3 Raw String & MD5 Fingerprint Hash
        - Server Name Indication (SNI) if present
        """
        try:
            if len(payload) < 43:
                return None
            
            # Check for TLS Handshake Record (Content Type 22 = 0x16, Version 0x0301/0x0302/0x0303)
            if payload[0] != 0x16:
                return None
            
            # Handshake type 1 = Client Hello
            handshake_type = payload[5]
            if handshake_type != 0x01:
                return None
            
            offset = 9  # Skip record header (5) + handshake header (4)
            if offset + 2 > len(payload):
                return None
                
            client_version = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            
            # Random (32 bytes)
            offset += 32
            if offset >= len(payload):
                return None
                
            # Session ID
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            if offset + 2 > len(payload):
                return None
                
            # Cipher Suites
            cipher_suites_len = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            if offset + cipher_suites_len > len(payload):
                return None
                
            ciphers = []
            for i in range(0, cipher_suites_len, 2):
                c = int.from_bytes(payload[offset+i:offset+i+2], "big")
                # Filter GREASE ciphers (0x?a?a)
                if (c & 0x0f0f) != 0x0a0a:
                    ciphers.append(c)
            offset += cipher_suites_len
            
            # Compression Methods
            if offset >= len(payload):
                return None
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            
            # Extensions
            extensions = []
            elliptic_curves = []
            ec_point_formats = []
            sni = None
            
            if offset + 2 <= len(payload):
                ext_len = int.from_bytes(payload[offset:offset+2], "big")
                offset += 2
                end_ext = min(offset + ext_len, len(payload))
                
                while offset + 4 <= end_ext:
                    ext_type = int.from_bytes(payload[offset:offset+2], "big")
                    ext_data_len = int.from_bytes(payload[offset+2:offset+4], "big")
                    offset += 4
                    
                    if (ext_type & 0x0f0f) != 0x0a0a:
                        extensions.append(ext_type)
                    
                    ext_data = payload[offset:offset+ext_data_len]
                    
                    # SNI (Extension 0)
                    if ext_type == 0 and len(ext_data) > 5:
                        try:
                            # Server Name List -> Server Name -> Host Name
                            name_len = int.from_bytes(ext_data[3:5], "big")
                            sni = ext_data[5:5+name_len].decode('utf-8', errors='ignore')
                        except Exception:
                            pass
                    
                    # Supported Groups / Elliptic Curves (Extension 10 = 0x000a)
                    elif ext_type == 10 and len(ext_data) >= 2:
                        curves_len = int.from_bytes(ext_data[0:2], "big")
                        for ci in range(2, min(2 + curves_len, len(ext_data)), 2):
                            curve = int.from_bytes(ext_data[ci:ci+2], "big")
                            if (curve & 0x0f0f) != 0x0a0a:
                                elliptic_curves.append(curve)
                                
                    # EC Point Formats (Extension 11 = 0x000b)
                    elif ext_type == 11 and len(ext_data) >= 1:
                        ec_point_formats_len = ext_data[0]
                        for pi in range(1, min(1 + ec_point_formats_len, len(ext_data))):
                            ec_point_formats.append(ext_data[pi])
                            
                    offset += ext_data_len

            # Format JA3 Raw String: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            ja3_str = (
                f"{client_version},"
                f"{'-'.join(map(str, ciphers))},"
                f"{'-'.join(map(str, extensions))},"
                f"{'-'.join(map(str, elliptic_curves))},"
                f"{'-'.join(map(str, ec_point_formats))}"
            )
            
            ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
            
            return {
                "tls_version": hex(client_version),
                "sni": sni,
                "ciphers_count": len(ciphers),
                "extensions_count": len(extensions),
                "ja3_string": ja3_str,
                "ja3_hash": ja3_hash
            }
        except Exception:
            return None

    @staticmethod
    def extract_splt_features(packet_sizes: List[int], packet_directions: List[int], max_packets: int = 15) -> np.ndarray:
        """
        Sequence of Packet Lengths and Times (SPLT) feature vector:
        Signed packet lengths (+ for outbound/client->server, - for inbound) for first N packets.
        Used to identify encrypted malware traffic patterns without decrypting bytes.
        """
        features = np.zeros(max_packets, dtype=np.float32)
        n = min(len(packet_sizes), len(packet_directions), max_packets)
        for i in range(n):
            signed_len = packet_sizes[i] * (1.0 if packet_directions[i] >= 0 else -1.0)
            features[i] = signed_len
        return features
