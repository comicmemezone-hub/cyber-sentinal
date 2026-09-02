"""
Method 1: Continuous PCAP Stream Engine
Replays authentic benchmark PCAP datasets sequentially at configurable wire velocity.
"""

import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from diode_sentinel.engine.diode_ingest import FastPcapParser, DiodePacket
from diode_sentinel.engine.pipeline import ThreatPipeline


class ContinuousPcapStreamer:
    """Streams real binary PCAP captures into the unidirectional diode in a continuous loop."""

    def __init__(self, pipeline: ThreatPipeline):
        self.pipeline = pipeline
        self.is_running = False
        self.rate_pps = 100
        self.total_streamed = 0
        self.current_scenario = "IDLE"
        self._thread: Optional[threading.Thread] = None

    def start(self, rate_pps: int = 100) -> Dict[str, Any]:
        if self.is_running:
            return {"status": "ALREADY_RUNNING", "packets": self.total_streamed}
        
        self.rate_pps = max(10, min(5000, rate_pps))
        self.is_running = True
        self._thread = threading.Thread(target=self._stream_loop, daemon=True)
        self._thread.start()
        return {"status": "RUNNING", "rate_pps": self.rate_pps}

    def stop(self) -> Dict[str, Any]:
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self.current_scenario = "STOPPED"
        return {"status": "STOPPED", "total_streamed": self.total_streamed}

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "rate_pps": self.rate_pps,
            "total_streamed": self.total_streamed,
            "current_scenario": self.current_scenario
        }

    def _stream_loop(self):
        candidates = [
            Path(__file__).resolve().parent.parent.parent / "datasets",
            Path(__file__).resolve().parent.parent / "datasets",
            Path("datasets").resolve(),
            Path("../datasets").resolve()
        ]
        # Stream authentic clean benign enterprise traffic by default (0 baseline threats)
        benign_files = list((base_dir / "benign").glob("*.pcap"))
        pcap_files = benign_files if benign_files else [base_dir / "benign" / "normal_traffic.pcap"]
        pcap_files = [p for p in pcap_files if p.exists()]
        if not pcap_files:
            pcap_files = sorted(list(base_dir.rglob("*.pcap")))
        
        if not pcap_files:
            return

        delay = 1.0 / self.rate_pps

        while self.is_running:
            for pcap_file in pcap_files:
                if not self.is_running:
                    break
                
                self.current_scenario = pcap_file.stem
                try:
                    packets = list(FastPcapParser.parse_pcap_file(str(pcap_file)))
                    if packets:
                        base_ts = time.time()
                        first_pcap_ts = packets[0].timestamp
                        for pkt in packets:
                            if not self.is_running:
                                break
                            # Preserve authentic relative timing from PCAP
                            pkt.timestamp = base_ts + (pkt.timestamp - first_pcap_ts)
                            self.pipeline.process_packet(pkt)
                            self.total_streamed += 1
                            time.sleep(delay)
                except Exception:
                    pass

                time.sleep(0.5)
