"""
Generate pre-built sample PCAP captures for the 7 demo scenarios.
Saves to datasets/benign/ and datasets/attacks/
"""

from pathlib import Path
from diode_sentinel.simulator.pcap_writer import PcapWriter
from diode_sentinel.simulator.attack_scenarios import AttackScenarios


def generate_demo_pcaps():
    base_dir = Path("datasets")
    benign_dir = base_dir / "benign"
    attacks_dir = base_dir / "attacks"
    benign_dir.mkdir(parents=True, exist_ok=True)
    attacks_dir.mkdir(parents=True, exist_ok=True)

    # 1. Benign normal traffic
    benign_pkts = [AttackScenarios.generate_benign_packet() for _ in range(500)]
    PcapWriter.write_packets_to_pcap(benign_pkts, str(benign_dir / "normal_traffic.pcap"))
    print("[+] Generated datasets/benign/normal_traffic.pcap")

    # 2. Attacks
    scenarios = [
        ("ddos.pcap", AttackScenarios.generate_syn_flood()),
        ("beacon.pcap", AttackScenarios.generate_c2_beacon()),
        ("dns_tunnel.pcap", AttackScenarios.generate_dns_tunnel()),
        ("dga.pcap", AttackScenarios.generate_dga_queries()),
        ("encrypted_malware.pcap", AttackScenarios.generate_tls_malware_session()),
        ("scan.pcap", AttackScenarios.generate_port_scan()),
        ("exfiltration.pcap", AttackScenarios.generate_data_exfiltration())
    ]

    for fname, pkts in scenarios:
        path = attacks_dir / fname
        PcapWriter.write_packets_to_pcap(pkts, str(path))
        print(f"[+] Generated datasets/attacks/{fname}")


if __name__ == "__main__":
    generate_demo_pcaps()
