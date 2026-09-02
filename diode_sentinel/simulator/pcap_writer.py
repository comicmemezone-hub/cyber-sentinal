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
        
        payload = pkt.payload
        if pkt.dns_info and not payload:
            domain = pkt.dns_info.get("domain", "google.com")
            rec_type = pkt.dns_info.get("record_type", "A")
            qtype = 16 if rec_type == "TXT" else 1
            hdr = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
            qname = b""
            for part in domain.strip('.').split('.'):
                p_bytes = part.encode('utf-8', errors='ignore')
                qname += bytes([len(p_bytes)]) + p_bytes
            qname += b"\x00"
            payload = hdr + qname + struct.pack('!HH', qtype, 1)

        elif pkt.tls_info and not payload:
            sni = pkt.tls_info.get("sni", "")
            sni_bytes = sni.encode('utf-8') if sni else b""
            server_name_ext = b""
            if sni_bytes:
                server_name_ext = struct.pack('!HHH', 0, len(sni_bytes) + 5, len(sni_bytes) + 3) + b'\x00' + struct.pack('!H', len(sni_bytes)) + sni_bytes
            
            ext_data = server_name_ext
            ext_len = len(ext_data)
            ext_block = struct.pack('!H', ext_len) + ext_data if ext_len > 0 else b""
            ciphers = struct.pack('!HHHH', 6, 0xc02f, 0xc030, 0xcca8)
            client_random = b'\x01' * 32
            ch_body = struct.pack('!H', 0x0303) + client_random + b'\x00' + ciphers + b'\x01\x00' + ext_block
            ch_len = len(ch_body)
            ch_hdr = struct.pack('!B', 1) + bytes([(ch_len >> 16) & 0xff, (ch_len >> 8) & 0xff, ch_len & 0xff])
            rec_body = ch_hdr + ch_body
            rec_hdr = struct.pack('!BHH', 0x16, 0x0301, len(rec_body))
            payload = rec_hdr + rec_body

        elif not payload and pkt.size > 54:
            payload = b"\x00" * max(0, pkt.size - 54)

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
            transport_payload = tcp_hdr + payload
            proto_num = 6
        else:
            # UDP Header (8 bytes)
            udp_len = 8 + len(payload)
            udp_hdr = struct.pack('!HHHH', pkt.src_port, pkt.dst_port, udp_len, 0)
            transport_payload = udp_hdr + payload
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
