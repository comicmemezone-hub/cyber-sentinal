"""
DiodeSentinel - PCAP Writer Utility
Exports DiodePacket streams to standard binary libpcap files for Wireshark inspection
"""

import struct
import socket
import time
from typing import List
from diode_sentinel.engine.diode_ingest import DiodePacket


class PcapWriter:
    """Writes DiodePacket objects into standard PCAP files."""

    PCAP_GLOBAL_HEADER = struct.pack(
        '<IHHiIII',
        0xa1b2c3d4,  # Magic Number (Microsecond resolution)
        2,           # Major Version
        4,           # Minor Version
        0,           # ThisZone (GMT)
        0,           # SigFigs
        65535,       # SnapLen
        1            # LinkType: Ethernet (1)
    )

    @classmethod
    def write_packets_to_pcap(cls, packets: List[DiodePacket], filepath: str):
        """Write a list of DiodePacket objects to a binary .pcap file."""
        with open(filepath, 'wb') as f:
            f.write(cls.PCAP_GLOBAL_HEADER)
            
            for pkt in packets:
                raw_frame = cls._synthesize_ethernet_frame(pkt)
                ts_sec = int(pkt.timestamp)
                ts_usec = int((pkt.timestamp - ts_sec) * 1_000_000)
                incl_len = len(raw_frame)
                orig_len = incl_len
                
                # 16-byte Packet Header
                pkt_hdr = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
                f.write(pkt_hdr)
                f.write(raw_frame)

    @classmethod
    def _synthesize_ethernet_frame(cls, pkt: DiodePacket) -> bytes:
        """Construct raw Ethernet + IP + TCP/UDP frame for PCAP serialization."""
        eth_dst = b'\xaa\xbb\xcc\xdd\xee\x11'
        eth_src = b'\xaa\xbb\xcc\xdd\xee\x22'
        eth_type = struct.pack('!H', 0x0800)  # IPv4
        
        # Build transport layer
        if pkt.protocol == "TCP":
            flags = 0
            if pkt.tcp_flags.get("fin"): flags |= 0x01
            if pkt.tcp_flags.get("syn"): flags |= 0x02
            if pkt.tcp_flags.get("rst"): flags |= 0x04
            if pkt.tcp_flags.get("psh"): flags |= 0x08
            if pkt.tcp_flags.get("ack"): flags |= 0x10
            if pkt.tcp_flags.get("urg"): flags |= 0x20
            
            # 20 bytes TCP Header
            tcp_hdr = struct.pack(
                '!HHIIBBHHH',
                pkt.src_port, pkt.dst_port,
                1000, 0,
                (5 << 4), flags,
                8192, 0, 0
            )
            transport_payload = tcp_hdr + pkt.payload
            proto_num = 6
        else:
            # UDP Header (8 bytes)
            udp_len = 8 + len(pkt.payload)
            udp_hdr = struct.pack('!HHHH', pkt.src_port, pkt.dst_port, udp_len, 0)
            transport_payload = udp_hdr + pkt.payload
            proto_num = 17

        # IP Header (20 bytes)
        src_bytes = socket.inet_aton(pkt.src_ip)
        dst_bytes = socket.inet_aton(pkt.dst_ip)
        total_ip_len = 20 + len(transport_payload)
        
        ip_hdr = struct.pack(
            '!BBHHHBBH4s4s',
            0x45, 0,
            total_ip_len,
            54321, 0,
            64, proto_num,
            0,
            src_bytes, dst_bytes
        )
        
        return eth_dst + eth_src + eth_type + ip_hdr + transport_payload
