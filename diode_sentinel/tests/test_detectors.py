"""
DiodeSentinel - Automated Threat Detector Unit & Integration Tests
Validates detection accuracy, alert schema adherence, and quantitative evidence for all 6 threat vectors.
"""

import unittest
import time
import os
from pathlib import Path

from diode_sentinel.engine.pipeline import ThreatPipeline
from diode_sentinel.engine.feature_extractor import FeatureExtractor
from diode_sentinel.engine.diode_ingest import FastPcapParser, DiodePacket
from diode_sentinel.simulator.attack_scenarios import AttackScenarios
from diode_sentinel.simulator.pcap_writer import PcapWriter


class TestDiodeSentinelDetectors(unittest.TestCase):

    def setUp(self):
        self.pipeline = ThreatPipeline()

    def test_shannon_entropy_calculation(self):
        """Test Shannon entropy calculation on known strings."""
        # Single repeating character has 0 entropy
        self.assertAlmostEqual(FeatureExtractor.calculate_shannon_entropy("aaaaaaa"), 0.0, places=4)
        
        # High-entropy random alphanumeric string
        entropy = FeatureExtractor.calculate_shannon_entropy("d8f319ac7b8e14f092e3")
        self.assertGreater(entropy, 3.2)

    def test_threat_a_syn_flood_detection(self):
        """Threat A: Verify TCP SYN Flood triggers VOLUMETRIC_DDOS alert."""
        packets = AttackScenarios.generate_syn_flood(target_ip="10.0.1.50", count=60)
        alerts_raised = []
        for pkt in packets:
            alerts = self.pipeline.process_packet(pkt)
            alerts_raised.extend(alerts)

        self.assertGreater(len(alerts_raised), 0, "Expected at least one DDoS alert")
        alert = alerts_raised[0]
        self.assertEqual(alert["threat_class"], "VOLUMETRIC_DDOS")
        self.assertIn("SYN", alert["subtype"])
        self.assertIn("syn_to_ack_ratio", alert["evidence"])
        self.assertGreaterEqual(alert["confidence_score"], 0.70)

    def test_threat_b_c2_beaconing_detection(self):
        """Threat B: Verify periodic heartbeat flows trigger BOTNET_C2_BEACONING."""
        # 6 periodic packets with interval 3.0s (IAT jitter < 0.05)
        packets = AttackScenarios.generate_c2_beacon(
            bot_ip="10.0.1.105",
            c2_ip="198.51.100.22",
            interval_sec=3.0,
            beacon_count=6
        )
        alerts_raised = []
        for pkt in packets:
            alerts = self.pipeline.process_packet(pkt)
            alerts_raised.extend(alerts)

        self.assertGreater(len(alerts_raised), 0, "Expected C2 beacon alert")
        alert = alerts_raised[0]
        self.assertEqual(alert["threat_class"], "BOTNET_C2_BEACONING")
        self.assertLess(alert["evidence"]["coefficient_of_variation"], 0.15)
        self.assertAlmostEqual(alert["evidence"]["mean_interval_sec"], 3.0, delta=0.2)

    def test_threat_c_dns_tunneling_detection(self):
        """Threat C1: Verify high-entropy DNS query triggers DGA_DNS_TUNNEL."""
        packets = AttackScenarios.generate_dns_tunnel(source_ip="10.0.1.77", count=3)
        alerts_raised = []
        for pkt in packets:
            alerts = self.pipeline.process_packet(pkt)
            alerts_raised.extend(alerts)

        self.assertGreater(len(alerts_raised), 0, "Expected DNS tunneling alert")
        alert = alerts_raised[0]
        self.assertEqual(alert["threat_class"], "DGA_DNS_TUNNEL")
        self.assertGreater(alert["evidence"]["shannon_entropy"], 3.3)
        self.assertIn("subdomain_payload", alert["evidence"])

    def test_threat_d_encrypted_malware_ja3(self):
        """Threat D: Verify Cobalt Strike TLS Client Hello triggers ENCRYPTED_MALWARE without payload decryption."""
        packets = AttackScenarios.generate_tls_malware_session(
            source_ip="10.0.1.18",
            c2_ip="203.0.113.89",
            malware_family="Cobalt Strike"
        )
        alerts_raised = []
        for pkt in packets:
            alerts = self.pipeline.process_packet(pkt)
            alerts_raised.extend(alerts)

        self.assertGreater(len(alerts_raised), 0, "Expected encrypted malware alert")
        alert = alerts_raised[0]
        self.assertEqual(alert["threat_class"], "ENCRYPTED_MALWARE")
        self.assertEqual(alert["evidence"]["malware_family"], "Cobalt Strike")
        self.assertEqual(alert["evidence"]["ja3_fingerprint"], "a0e9f5d64349fb13191bc781f81f42e1")

    def test_threat_e_port_scan_recon(self):
        """Threat E: Verify vertical 25-port scan triggers PORT_SCAN_RECON."""
        packets = AttackScenarios.generate_port_scan(
            scanner_ip="10.0.1.99",
            target_ip="10.0.1.200",
            scan_type="vertical"
        )
        alerts_raised = []
        for pkt in packets:
            alerts = self.pipeline.process_packet(pkt)
            alerts_raised.extend(alerts)

        self.assertGreater(len(alerts_raised), 0, "Expected port scan alert")
        alert = alerts_raised[0]
        self.assertEqual(alert["threat_class"], "PORT_SCAN_RECON")
        self.assertGreaterEqual(alert["evidence"]["unique_ports_scanned"], 12)

    def test_threat_f_data_exfiltration(self):
        """Threat F: Verify high-volume asymmetric egress triggers DATA_EXFILTRATION."""
        packets = AttackScenarios.generate_data_exfiltration(
            source_ip="10.0.1.44",
            dropzone_ip="185.220.101.5",
            volume_mb=3.0
        )
        alerts_raised = []
        for pkt in packets:
            alerts = self.pipeline.process_packet(pkt)
            alerts_raised.extend(alerts)

        self.assertGreater(len(alerts_raised), 0, "Expected data exfiltration alert")
        alert = alerts_raised[0]
        self.assertEqual(alert["threat_class"], "DATA_EXFILTRATION")
        self.assertGreaterEqual(alert["evidence"]["outbound_inbound_ratio"], 8.0)

    def test_pcap_serialization_and_replay(self):
        """Verify PCAP writer and FastPcapParser roundtrip serialization."""
        tmp_pcap = Path("diode_sentinel/data/test_temp.pcap")
        test_pkts = AttackScenarios.generate_syn_flood(count=10)
        
        try:
            PcapWriter.write_packets_to_pcap(test_pkts, str(tmp_pcap))
            self.assertTrue(tmp_pcap.exists())
            
            parsed_pkts = list(FastPcapParser.parse_pcap_file(str(tmp_pcap)))
            self.assertEqual(len(parsed_pkts), 10)
            self.assertEqual(parsed_pkts[0].protocol, "TCP")
        finally:
            if tmp_pcap.exists():
                tmp_pcap.unlink()


if __name__ == "__main__":
    unittest.main()
