"""
Method 2: Live Browser & DNS Passive TAP
Captures real-time web browsing traffic, TLS ClientHello handshakes, and DNS lookups
directly from Chrome, Edge, Firefox, or curl without Administrator permissions.
"""

import socket
import select
import threading
import time
import re
from typing import Dict, Any, Optional
from diode_sentinel.engine.diode_ingest import DiodePacket
from diode_sentinel.engine.feature_extractor import FeatureExtractor
from diode_sentinel.engine.pipeline import ThreatPipeline


class BrowserDnsTap:
    """Runs a local transparent passive TAP proxy on port 8080 to capture live browser frames."""

    def __init__(self, pipeline: ThreatPipeline, port: int = 8080):
        self.pipeline = pipeline
        self.port = port
        self.is_running = False
        self.total_packets_tapped = 0
        self.last_tapped_domain: str = "None"
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> Dict[str, Any]:
        if self.is_running:
            return {"status": "ALREADY_RUNNING", "port": self.port, "tapped": self.total_packets_tapped}

        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("127.0.0.1", self.port))
            self._server_sock.listen(50)
            self._server_sock.settimeout(1.0)
            self.is_running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            return {
                "status": "RUNNING",
                "port": self.port,
                "proxy_url": f"http://127.0.0.1:{self.port}",
                "message": f"Browser TAP active on 127.0.0.1:{self.port}"
            }
        except Exception as e:
            self.is_running = False
            return {"status": "ERROR", "message": str(e)}

    def stop(self) -> Dict[str, Any]:
        self.is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None
        return {"status": "STOPPED", "total_tapped": self.total_packets_tapped}

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "port": self.port,
            "total_tapped": self.total_packets_tapped,
            "last_tapped_domain": self.last_tapped_domain
        }

    def _listen_loop(self):
        while self.is_running:
            try:
                client_sock, client_addr = self._server_sock.accept()
                threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                if not self.is_running:
                    break

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        try:
            client_sock.settimeout(3.0)
            request = client_sock.recv(4096)
            if not request:
                client_sock.close()
                return

            now = time.time()
            req_text = request.decode("latin-1", errors="ignore")
            first_line = req_text.split("\r\n")[0] if "\r\n" in req_text else ""
            
            # HTTPS CONNECT method
            if first_line.startswith("CONNECT"):
                parts = first_line.split(" ")
                if len(parts) >= 2:
                    host_port = parts[1]
                    host, port = host_port.split(":") if ":" in host_port else (host_port, 443)
                    port = int(port)
                    self.last_tapped_domain = host
                    self.total_packets_tapped += 1

                    # Connect to target remote server
                    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_sock.settimeout(5.0)
                    try:
                        remote_sock.connect((host, port))
                        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    except Exception:
                        client_sock.close()
                        return

                    # Ingest Diode SYN & DNS frame
                    dns_info = {"query_name": host, "entropy": FeatureExtractor.calculate_shannon_entropy(host)}
                    syn_pkt = DiodePacket(
                        timestamp=now,
                        src_ip=client_addr[0],
                        dst_ip=socket.gethostbyname(host) if not host.replace(".", "").isdigit() else host,
                        src_port=client_addr[1],
                        dst_port=port,
                        protocol="TCP",
                        size=len(request),
                        tcp_flags={"SYN": True, "ACK": True},
                        dns_info=dns_info
                    )
                    self.pipeline.process_packet(syn_pkt)

                    # Inspect initial TLS ClientHello frame
                    tls_data = client_sock.recv(4096)
                    if tls_data and len(tls_data) >= 5 and tls_data[0] == 0x16:
                        tls_info = FeatureExtractor.parse_tls_client_hello(tls_data)
                        tls_pkt = DiodePacket(
                            timestamp=time.time(),
                            src_ip=client_addr[0],
                            dst_ip=syn_pkt.dst_ip,
                            src_port=client_addr[1],
                            dst_port=port,
                            protocol="TCP",
                            size=len(tls_data),
                            tcp_flags={"ACK": True, "PSH": True},
                            tls_info=tls_info
                        )
                        self.pipeline.process_packet(tls_pkt)
                        self.total_packets_tapped += 1
                        remote_sock.sendall(tls_data)

                    # Tunnel bidirectional stream
                    self._forward_stream(client_sock, remote_sock)
                    return

            # Standard HTTP GET/POST
            else:
                host_match = re.search(r"Host:\s*([^\r\n]+)", req_text, re.IGNORECASE)
                host = host_match.group(1).strip() if host_match else "unknown.com"
                self.last_tapped_domain = host
                self.total_packets_tapped += 1

                pkt = DiodePacket(
                    timestamp=now,
                    src_ip=client_addr[0],
                    dst_ip="127.0.0.1",
                    src_port=client_addr[1],
                    dst_port=80,
                    protocol="TCP",
                    size=len(request),
                    tcp_flags={"ACK": True, "PSH": True},
                    dns_info={"query_name": host, "entropy": FeatureExtractor.calculate_shannon_entropy(host)}
                )
                self.pipeline.process_packet(pkt)
                client_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h3>Cyber Sentinel Tapped</h3>")
                client_sock.close()

        except Exception:
            try: client_sock.close()
            except Exception: pass

    def _forward_stream(self, s1: socket.socket, s2: socket.socket):
        """Pass-through bidirectional socket pipe."""
        sockets = [s1, s2]
        try:
            while self.is_running:
                r, _, _ = select.select(sockets, [], [], 2.0)
                if not r: break
                for s in r:
                    data = s.recv(8192)
                    if not data: return
                    target = s2 if s is s1 else s1
                    target.sendall(data)
        except Exception:
            pass
        finally:
            try: s1.close()
            except Exception: pass
            try: s2.close()
            except Exception: pass
