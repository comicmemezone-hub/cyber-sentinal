"""
Method 3: Live Socket Attack Probe & Honeypot Listener
Listens on multiple decoy ports to intercept live Nmap port scans, socket probes,
and connection sweeps in real time without elevated raw socket permissions.
"""

import socket
import threading
import time
from typing import Dict, Any, List, Optional
from diode_sentinel.engine.diode_ingest import DiodePacket
from diode_sentinel.engine.pipeline import ThreatPipeline


class SocketProbeListener:
    """Listens on multiple TCP ports to intercept real live port scans and connection probes."""

    PROBE_PORTS = [21, 22, 23, 25, 53, 80, 443, 3389, 8080, 8443, 9000, 9200]

    def __init__(self, pipeline: ThreatPipeline, bind_host: str = "0.0.0.0"):
        self.pipeline = pipeline
        self.bind_host = bind_host
        self.is_running = False
        self.total_probes_intercepted = 0
        self.active_listeners: List[socket.socket] = []
        self._threads: List[threading.Thread] = []

    def start(self, bind_host: Optional[str] = None) -> Dict[str, Any]:
        if self.is_running:
            return {
                "status": "ALREADY_RUNNING",
                "bind_host": self.bind_host,
                "ports": len(self.active_listeners),
                "active_ports": self._active_ports(),
            }

        if bind_host:
            self.bind_host = bind_host
        self.is_running = True
        bound_ports = []

        for port in self.PROBE_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.bind_host, port))
                s.listen(20)
                s.settimeout(1.0)
                self.active_listeners.append(s)
                bound_ports.append(port)

                t = threading.Thread(target=self._port_listener, args=(s, port), daemon=True)
                t.start()
                self._threads.append(t)
            except Exception:
                # Port might be in use or restricted
                pass

        if not bound_ports:
            self.is_running = False
            return {
                "status": "ERROR",
                "bind_host": self.bind_host,
                "bound_ports": [],
                "count": 0,
                "message": "No probe ports could be opened. Stop conflicting services or run with sufficient permissions.",
            }

        return {
            "status": "RUNNING",
            "bind_host": self.bind_host,
            "bound_ports": bound_ports,
            "count": len(bound_ports),
            "message": f"Active socket probe listener is reachable on {self.bind_host} across {len(bound_ports)} ports."
        }

    def stop(self) -> Dict[str, Any]:
        self.is_running = False
        for s in self.active_listeners:
            try:
                s.close()
            except Exception:
                pass
        self.active_listeners.clear()
        self._threads.clear()
        return {"status": "STOPPED", "probes_intercepted": self.total_probes_intercepted}

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "bind_host": self.bind_host,
            "active_ports": self._active_ports(),
            "active_endpoints": [f"{self.bind_host}:{p}" for p in self._active_ports()],
            "total_probes": self.total_probes_intercepted
        }

    def _active_ports(self) -> List[int]:
        ports = []
        for s in self.active_listeners:
            try:
                ports.append(s.getsockname()[1])
            except Exception:
                pass
        return ports

    def _port_listener(self, server_sock: socket.socket, port: int):
        while self.is_running:
            try:
                client_sock, client_addr = server_sock.accept()
                self.total_probes_intercepted += 1
                now = time.time()
                local_ip = client_sock.getsockname()[0]

                pkt = DiodePacket(
                    timestamp=now,
                    src_ip=client_addr[0],
                    dst_ip=local_ip,
                    src_port=client_addr[1],
                    dst_port=port,
                    protocol="TCP",
                    size=64,
                    tcp_flags={"SYN": True}
                )
                self.pipeline.process_packet(pkt)
                client_sock.close()
            except socket.timeout:
                continue
            except Exception:
                if not self.is_running:
                    break

    def trigger_live_scan_sweep(self, target_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """Programmatically fire real socket connection attempts against a target IP."""
        target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000]
        
        def _sweep():
            for p in target_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.05)
                    s.connect_ex((target_ip, p))
                    s.close()
                    time.sleep(0.02)
                except Exception:
                    pass

        threading.Thread(target=_sweep, daemon=True).start()
        return {"status": "SWEEP_TRIGGERED", "target_ip": target_ip, "ports_swept": len(target_ports)}
