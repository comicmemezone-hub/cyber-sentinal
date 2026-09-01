"""
DiodeSentinel Detection Models Package
"""

from diode_sentinel.models.threat_db import lookup_ja3, is_benign_ja3
from diode_sentinel.models.ddos_detector import DDoSDetector
from diode_sentinel.models.c2_detector import C2BeaconDetector
from diode_sentinel.models.dns_detector import DNSTunnelDetector
from diode_sentinel.models.tls_malware_detector import TLSMalwareDetector
from diode_sentinel.models.recon_detector import PortScanDetector
from diode_sentinel.models.exfil_detector import DataExfiltrationDetector

__all__ = [
    "DDoSDetector",
    "C2BeaconDetector",
    "DNSTunnelDetector",
    "TLSMalwareDetector",
    "PortScanDetector",
    "DataExfiltrationDetector",
    "lookup_ja3",
    "is_benign_ja3"
]
