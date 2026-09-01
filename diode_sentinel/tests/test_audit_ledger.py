"""
DiodeSentinel - Cryptographic Ledger & SQLite Storage Tests
Verifies tamper-evident SHA-256 hash chaining and persistent alert storage.
"""

import unittest
import os
from pathlib import Path
from diode_sentinel.blockchain.audit_ledger import HashChainLedger
from diode_sentinel.storage.sqlite_store import SQLiteStore


class TestAuditLedgerAndStorage(unittest.TestCase):

    def setUp(self):
        self.tmp_ledger = Path("diode_sentinel/data/test_audit.jsonl")
        self.tmp_db = Path("diode_sentinel/data/test_store.db")
        if self.tmp_ledger.exists():
            self.tmp_ledger.unlink()
        if self.tmp_db.exists():
            self.tmp_db.unlink()

        self.ledger = HashChainLedger(ledger_file=str(self.tmp_ledger))
        self.store = SQLiteStore(db_path=str(self.tmp_db))

    def tearDown(self):
        if self.tmp_ledger.exists():
            self.tmp_ledger.unlink()
        if self.tmp_db.exists():
            self.tmp_db.unlink()

    def test_hash_chain_append_and_verify(self):
        """Verify that appending blocks creates valid cryptographic SHA-256 links."""
        alert_1 = {
            "alert_id": "ALT-1001",
            "threat_class": "VOLUMETRIC_DDOS",
            "severity": "CRITICAL",
            "summary": "SYN Flood Test"
        }
        alert_2 = {
            "alert_id": "ALT-1002",
            "threat_class": "BOTNET_C2_BEACONING",
            "severity": "HIGH",
            "summary": "Cobalt Strike C2 Test"
        }

        block_1 = self.ledger.append_alert(alert_1)
        block_2 = self.ledger.append_alert(alert_2)

        self.assertEqual(block_1.index, 1)
        self.assertEqual(block_2.index, 2)
        self.assertEqual(block_2.previous_hash, block_1.hash)

        # Verify integrity
        integrity = self.ledger.verify_integrity()
        self.assertTrue(integrity["valid"])
        self.assertEqual(integrity["chain_length"], 3)  # Genesis + 2 alerts

    def test_hash_chain_tamper_detection(self):
        """Verify that modifying a block invalidates the hash chain."""
        alert = {"alert_id": "ALT-999", "threat_class": "DATA_EXFILTRATION", "severity": "HIGH"}
        self.ledger.append_alert(alert)

        # Tamper with block 1 payload
        self.ledger.chain[1].alert_data["severity"] = "LOW"  # Maliciously altered

        integrity = self.ledger.verify_integrity()
        self.assertFalse(integrity["valid"])
        self.assertIn("tampered content", integrity["error"])

    def test_sqlite_insert_and_query(self):
        """Verify SQLite insertion and filtering."""
        sample_alert = {
            "alert_id": "ALT-SQL-01",
            "timestamp": "2026-08-26T10:00:00Z",
            "flow_id": "10.0.1.1:443 -> 10.0.1.2:80 [TCP]",
            "src_ip": "10.0.1.1",
            "src_port": 443,
            "dst_ip": "10.0.1.2",
            "dst_port": 80,
            "protocol": "TCP",
            "threat_class": "PORT_SCAN_RECON",
            "subtype": "VERTICAL_SCAN",
            "severity": "HIGH",
            "confidence_score": 0.92,
            "mitre_technique": "T1046",
            "summary": "Port scan detected",
            "evidence": {"ports": 25},
            "flow_snapshot": {"pps": 100}
        }
        self.store.insert_alert(sample_alert)
        alerts = self.store.get_recent_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_id"], "ALT-SQL-01")
        self.assertEqual(alerts[0]["evidence"]["ports"], 25)


if __name__ == "__main__":
    unittest.main()
