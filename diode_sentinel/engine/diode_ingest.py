"""
DiodeSentinel - Unidirectional Data Diode Ingest Module
Strictly Read-Only Ingestion for Network Streams and PCAP Captures
Zero Return-Path Guaranteed
"""

import struct
import socket
from typing import Generator, Dict, Any, Optional
from diode_sentinel.engine.feature_extractor import FeatureExtractor


class DiodePacket:
    """Represents a passively observed network packet crossing the hardware diode."""

    def __init__(
        self,
        timestamp: float,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        size: int,
        payload: bytes = b"",
        tcp_flags: Optional[Dict[str, bool]] = None,
        dns_info: Optional[Dict[str, Any]] = None,
        tls_info: Optional[Dict[str, Any]] = None
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol.upper()
        self.size = size
        self.payload = payload
        self.tcp_flags = tcp_flags or {}
        self.dns_info = dns_info
        self.tls_info = tls_info

    def __repr__(self) -> str:
        return f"<DiodePacket {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol}] {self.size}B>"


class FastPcapParser:
    """
    Pure Python zero-dependency high-speed PCAP parser.
    Reads global PCAP header (24 bytes) and per-packet headers (16 bytes).
    Extracts IPv4, TCP, UDP, DNS queries, and TLS Client Hello fingerprints.
    """

    PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4
    PCAP_MAGIC_NANOSECONDS = 0xa1b23c4d
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1

    @classmethod
    def parse_pcap_file(cls, filepath: str) -> Generator[DiodePacket, None, None]:
        with open(filepath, 'rb') as f:
            header = f.read(24)
            if len(header) < 24:
                return

            magic = struct.unpack('<I', header[:4])[0]
            is_swapped = (magic == cls.PCAP_MAGIC_SWAPPED)
            endian = '>' if is_swapped else '<'
            
            # Read packet records
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_hdr)
                ts = ts_sec + (ts_usec / 1_000_000.0)
                
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                packet = cls.parse_raw_ethernet(pkt_data, ts)
                if packet:
                    yield packet

    @classmethod
    def parse_raw_ethernet(cls, data: bytes, timestamp: float) -> Optional[DiodePacket]:
        """Parses Ethernet II frame -> IP -> TCP/UDP/DNS/TLS."""
        if len(data) < 14:
            return None

        eth_type = struct.unpack('!H', data[12:14])[0]
        offset = 14

        # Handle 802.1Q VLAN Tag
        if eth_type == 0x8100:
            eth_type = struct.unpack('!H', data[16:18])[0]
            offset = 18

        # Only process IPv4 (0x0800) for high-performance flow tracking
        if eth_type != 0x0800 or len(data) < offset + 20:
            return None

        ip_header = data[offset:offset+20]
        ihl = (ip_header[0] & 0x0F) * 4
        total_len = struct.unpack('!H', ip_header[2:4])[0]
        protocol_num = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])
        
        ip_payload = data[offset + ihl: offset + total_len]
        
        tcp_flags = None
        dns_info = None
        tls_info = None
        src_port = 0
        dst_port = 0
        protocol_str = "OTHER"

        # TCP (Protocol 6)
        if protocol_num == 6 and len(ip_payload) >= 20:
            protocol_str = "TCP"
            src_port, dst_port = struct.unpack('!HH', ip_payload[:4])
            tcp_offset = ((ip_payload[12] >> 4) & 0x0F) * 4
            flags_byte = ip_payload[13]
            
            tcp_flags = {
                "fin": bool(flags_byte & 0x01),
                "syn": bool(flags_byte & 0x02),
                "rst": bool(flags_byte & 0x04),
                "psh": bool(flags_byte & 0x08),
                "ack": bool(flags_byte & 0x10),
                "urg": bool(flags_byte & 0x20)
            }
            
            tcp_payload = ip_payload[tcp_offset:]
            # Check for TLS Client Hello (ports 443, 8443, etc.)
            if len(tcp_payload) > 5 and tcp_payload[0] == 0x16:
                tls_info = FeatureExtractor.parse_tls_client_hello(tcp_payload)

        # UDP (Protocol 17)
        elif protocol_num == 17 and len(ip_payload) >= 8:
            protocol_str = "UDP"
            src_port, dst_port = struct.unpack('!HH', ip_payload[:4])
            udp_payload = ip_payload[8:]
            
            # DNS parsing (Port 53 or mDNS 5353)
            if (dst_port == 53 or src_port == 53) and len(udp_payload) >= 12:
                dns_info = cls._parse_dns_query(udp_payload)

        return DiodePacket(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol_str,
            size=len(data),
            payload=ip_payload,
            tcp_flags=tcp_flags,
            dns_info=dns_info,
            tls_info=tls_info
        )

    @classmethod
    def _parse_dns_query(cls, payload: bytes) -> Optional[Dict[str, Any]]:
        """Extract DNS Question Name and Record Type passively."""
        try:
            qdcount = struct.unpack('!H', payload[4:6])[0]
            if qdcount < 1:
                return None
                
            offset = 12
            labels = []
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    # DNS pointer compression
                    offset += 2
                    break
                offset += 1
                if offset + length > len(payload):
                    break
                labels.append(payload[offset:offset+length].decode('utf-8', errors='ignore'))
                offset += length
                
            domain = ".".join(labels)
            if not domain:
                return None
                
            qtype = 1
            if offset + 2 <= len(payload):
                qtype = struct.unpack('!H', payload[offset:offset+2])[0]
                
            type_map = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 10: "NULL", 255: "ANY"}
            record_type = type_map.get(qtype, f"TYPE_{qtype}")
            
            return FeatureExtractor.extract_dns_features(domain, record_type)
        except Exception:
            return None
