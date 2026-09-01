"""
Method 4: Npcap / WinPcap Kernel Driver Capture Engine
Uses low-level Npcap kernel driver if available to capture full Layer-2 promiscuous Ethernet frames.
"""

import ctypes
import os
import threading
import time
from typing import Dict, Any, Optional
from diode_sentinel.engine.diode_ingest import DiodePacket
from diode_sentinel.engine.pipeline import ThreatPipeline


class NpcapKernelEngine:
    """Reports Npcap availability.

    Actual Npcap frame capture still needs a pcap binding such as pyshark,
    scapy, or pcapy. This class must not claim capture is active until that
    driver-backed read loop exists.
    """

    def __init__(self, pipeline: ThreatPipeline):
        self.pipeline = pipeline
        self.is_running = False
        self.is_npcap_installed = self._detect_npcap()
        self.total_packets_captured = 0
        self._thread: Optional[threading.Thread] = None

    def _detect_npcap(self) -> bool:
        """Check if npcap or wpcap DLLs are registered in Windows System32."""
        for dll in ["wpcap.dll", "Packet.dll", "npcap.dll"]:
            try:
                ctypes.cdll.LoadLibrary(dll)
                return True
            except Exception:
                pass
        return False

    def get_status(self) -> Dict[str, Any]:
        return {
            "npcap_installed": self.is_npcap_installed,
            "is_running": self.is_running,
            "total_captured": self.total_packets_captured,
            "driver_name": "Npcap NDIS 6.0 Filter Driver" if self.is_npcap_installed else "Not Detected",
            "capture_supported": False,
            "download_url": "https://npcap.com/#download"
        }

    def start(self) -> Dict[str, Any]:
        if not self.is_npcap_installed:
            return {
                "status": "NPCAP_NOT_INSTALLED",
                "message": "Npcap kernel driver is not installed on this machine. Use Method 1 (Continuous PCAP Stream) or Method 2 (Live Browser TAP) instead!"
            }

        self.is_running = False
        return {
            "status": "NPCAP_CAPTURE_NOT_IMPLEMENTED",
            "message": "Npcap is installed, but this project does not yet include a driver-backed packet read loop."
        }

    def stop(self) -> Dict[str, Any]:
        self.is_running = False
        return {"status": "STOPPED", "total_captured": self.total_packets_captured}
