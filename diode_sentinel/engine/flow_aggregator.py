"""
DiodeSentinel - Flow Aggregator & Sliding Window State Tracker
Passive 5-tuple Flow State Accumulator for Unidirectional Traffic Streams
"""

import time
from collections import defaultdict
from typing import Dict, List, Optional, Any, Set


class FlowRecord:
    """Represents an aggregated network flow observed passively over the diode link."""

    def __init__(self, flow_key: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str):
        self.flow_key = flow_key
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol.upper()
        
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        
        # Volume counters
        self.packet_count = 0
        self.byte_count = 0
        self.outbound_packets = 0
        self.outbound_bytes = 0
        self.inbound_packets = 0
        self.inbound_bytes = 0
        
        # TCP Flags tracking
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        
        # Time series of packet arrivals and sizes for spectral & SPLT analysis
        self.timestamps: List[float] = []
        self.packet_sizes: List[int] = []
        self.packet_directions: List[int] = []  # +1 = Outbound (src->dst), -1 = Inbound (dst->src)
        
        # Layer 7 Protocol Metadata (Passive Ingest)
        self.dns_queries: List[Dict[str, Any]] = []
        self.ja3_fingerprint: Optional[str] = None
        self.ja3_details: Optional[Dict[str, Any]] = None
        self.sni: Optional[str] = None

    def add_packet(
        self,
        size: int,
        timestamp: float,
        is_outbound: bool = True,
        tcp_flags: Optional[Dict[str, bool]] = None,
        dns_info: Optional[Dict[str, Any]] = None,
        tls_info: Optional[Dict[str, Any]] = None
    ):
        """Update flow state with an incoming packet from the diode."""
        self.last_seen = timestamp
        self.packet_count += 1
        self.byte_count += size
        
        if is_outbound:
            self.outbound_packets += 1
            self.outbound_bytes += size
            direction = 1
        else:
            self.inbound_packets += 1
            self.inbound_bytes += size
            direction = -1
            
        # Keep bounded history of timestamps & sizes (e.g. max 100 packets per flow)
        if len(self.timestamps) < 100:
            self.timestamps.append(timestamp)
            self.packet_sizes.append(size)
            self.packet_directions.append(direction)
            
        if tcp_flags:
            if tcp_flags.get("syn", False):
                self.syn_count += 1
            if tcp_flags.get("ack", False):
                self.ack_count += 1
            if tcp_flags.get("fin", False):
                self.fin_count += 1
            if tcp_flags.get("rst", False):
                self.rst_count += 1

        if dns_info:
            self.dns_queries.append(dns_info)
            
        if tls_info and not self.ja3_fingerprint:
            self.ja3_fingerprint = tls_info.get("ja3_hash")
            self.ja3_details = tls_info
            self.sni = tls_info.get("sni")

    @property
    def duration_sec(self) -> float:
        return max(0.001, self.last_seen - self.first_seen)

    @property
    def packets_per_sec(self) -> float:
        return self.packet_count / self.duration_sec

    @property
    def bytes_per_sec(self) -> float:
        return self.byte_count / self.duration_sec

    @property
    def byte_ratio_out_to_in(self) -> float:
        """Ratio of outbound to inbound bytes (useful for exfiltration detection)."""
        if self.inbound_bytes == 0:
            return float(self.outbound_bytes) if self.outbound_bytes > 0 else 1.0
        return self.outbound_bytes / self.inbound_bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_key": self.flow_key,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration_sec": round(self.duration_sec, 2),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "outbound_bytes": self.outbound_bytes,
            "inbound_bytes": self.inbound_bytes,
            "pps": round(self.packets_per_sec, 1),
            "bps": round(self.bytes_per_sec, 1),
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "ja3_fingerprint": self.ja3_fingerprint,
            "sni": self.sni,
            "dns_query_count": len(self.dns_queries)
        }


class FlowAggregator:
    """Manages active flow tables and sliding-window statistics across all observed traffic."""

    def __init__(self, sliding_window_sec: float = 10.0, cleanup_interval_sec: float = 15.0):
        self.sliding_window_sec = sliding_window_sec
        self.cleanup_interval_sec = cleanup_interval_sec
        self.last_cleanup = time.time()
        
        # Key: "src_ip:src_port -> dst_ip:dst_port [PROTO]"
        self.flows: Dict[str, FlowRecord] = {}
        
        # Source IP and Destination IP aggregations for Host-level & Fan-out analysis
        self.src_ip_packets: Dict[str, int] = defaultdict(int)
        self.src_ip_bytes: Dict[str, int] = defaultdict(int)
        self.src_ip_syns: Dict[str, int] = defaultdict(int)
        self.src_ip_ports_accessed: Dict[str, Set[int]] = defaultdict(set)
        self.src_ip_dst_ips_accessed: Dict[str, Set[str]] = defaultdict(set)

        # Destination IP aggregation for target-based DDoS detection
        self.dst_ip_packets: Dict[str, int] = defaultdict(int)
        self.dst_ip_bytes: Dict[str, int] = defaultdict(int)
        self.dst_ip_syns: Dict[str, int] = defaultdict(int)
        self.dst_ip_acks: Dict[str, int] = defaultdict(int)
        self.dst_ip_first_seen: Dict[str, float] = {}
        self.dst_ip_last_seen: Dict[str, float] = {}
        
        # Global Sliding Window Rolling Packet & Byte counters
        self.total_packets_window = 0
        self.total_bytes_window = 0
        self.active_src_ips_window: List[str] = []
        self.active_dst_ips_window: List[str] = []
        self.active_dst_ports_window: List[int] = []

    def get_or_create_flow(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str
    ) -> FlowRecord:
        """Create or retrieve a flow record."""
        flow_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} [{protocol.upper()}]"
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowRecord(
                flow_key=flow_key,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol
            )
        return self.flows[flow_key]

    def ingest_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        size: int,
        timestamp: Optional[float] = None,
        is_outbound: bool = True,
        tcp_flags: Optional[Dict[str, bool]] = None,
        dns_info: Optional[Dict[str, Any]] = None,
        tls_info: Optional[Dict[str, Any]] = None
    ) -> FlowRecord:
        """Ingest single unidirectional packet and update flow and global trackers."""
        ts = timestamp or time.time()
        flow = self.get_or_create_flow(src_ip, src_port, dst_ip, dst_port, protocol)
        flow.add_packet(
            size=size,
            timestamp=ts,
            is_outbound=is_outbound,
            tcp_flags=tcp_flags,
            dns_info=dns_info,
            tls_info=tls_info
        )
        
        # Track host-level fan-out and volume
        self.src_ip_packets[src_ip] += 1
        self.src_ip_bytes[src_ip] += size
        if tcp_flags and tcp_flags.get("syn", False):
            self.src_ip_syns[src_ip] += 1
        self.src_ip_ports_accessed[src_ip].add(dst_port)
        self.src_ip_dst_ips_accessed[src_ip].add(dst_ip)

        # Track target/destination level volume & SYN/ACK for DDoS detection
        self.dst_ip_packets[dst_ip] += 1
        self.dst_ip_bytes[dst_ip] += size
        if dst_ip not in self.dst_ip_first_seen:
            self.dst_ip_first_seen[dst_ip] = ts
        self.dst_ip_last_seen[dst_ip] = ts
        if tcp_flags:
            if tcp_flags.get("syn", False):
                self.dst_ip_syns[dst_ip] += 1
            if tcp_flags.get("ack", False):
                self.dst_ip_acks[dst_ip] += 1
        
        # Windowed distribution trackers
        self.total_packets_window += 1
        self.total_bytes_window += size
        self.active_src_ips_window.append(src_ip)
        self.active_dst_ips_window.append(dst_ip)
        self.active_dst_ports_window.append(dst_port)
        
        # Periodic cleanup of expired records
        if ts - self.last_cleanup > self.cleanup_interval_sec:
            self.cleanup_expired(ts)
            
        return flow

    def get_dst_stats(self, dst_ip: str) -> Dict[str, Any]:
        """Return aggregated traffic metrics targeting a destination IP."""
        first_seen = self.dst_ip_first_seen.get(dst_ip, time.time())
        last_seen = self.dst_ip_last_seen.get(dst_ip, first_seen)
        duration = max(0.001, last_seen - first_seen)
        packets = self.dst_ip_packets.get(dst_ip, 0)
        bytes_count = self.dst_ip_bytes.get(dst_ip, 0)
        syns = self.dst_ip_syns.get(dst_ip, 0)
        acks = self.dst_ip_acks.get(dst_ip, 0)
        
        return {
            "packets": packets,
            "bytes": bytes_count,
            "syns": syns,
            "acks": acks,
            "duration_sec": duration,
            "pps": packets / duration,
            "bps": bytes_count / duration
        }

    def cleanup_expired(self, current_time: float):
        """Remove inactive flows exceeding the sliding window."""
        self.last_cleanup = current_time
        expired_keys = [
            k for k, flow in self.flows.items()
            if (current_time - flow.last_seen) > self.cleanup_interval_sec * 2
        ]
        for k in expired_keys:
            del self.flows[k]
            
        # Reset rolling window lists to prevent unbounded memory growth
        if len(self.active_src_ips_window) > 20000:
            self.active_src_ips_window = self.active_src_ips_window[-5000:]
            self.active_dst_ips_window = self.active_dst_ips_window[-5000:]
            self.active_dst_ports_window = self.active_dst_ports_window[-5000:]

    def get_all_active_flows(self) -> List[FlowRecord]:
        """Return only genuinely active flows within the sliding window and evict inactive ones."""
        now = time.time()
        expired_keys = [
            k for k, flow in self.flows.items()
            if (now - flow.last_seen) > self.sliding_window_sec
        ]
        for k in expired_keys:
            del self.flows[k]
        return list(self.flows.values())

    def get_fanout_stats(self, src_ip: str) -> Dict[str, Any]:
        """Return fanout breadth (unique ports and destinations probed)."""
        return {
            "unique_ports_count": len(self.src_ip_ports_accessed.get(src_ip, set())),
            "unique_ips_count": len(self.src_ip_dst_ips_accessed.get(src_ip, set())),
            "total_syn_count": self.src_ip_syns.get(src_ip, 0),
            "total_packet_count": self.src_ip_packets.get(src_ip, 0)
        }
