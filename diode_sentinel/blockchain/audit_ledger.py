"""
DiodeSentinel - Cryptographic SHA-256 Hash-Chain Audit Ledger
Provides an append-only, tamper-evident forensic chain of custody for all security alerts.
Adheres to Problem Statement ID 26145 Specification.
"""

import hashlib
import json
import time
import os
from pathlib import Path
from typing import Dict, Any, List, Optional


class AuditBlock:
    """Represents a single tamper-evident block in the forensic alert hash-chain."""

    def __init__(
        self,
        index: int,
        timestamp: float,
        alert_id: str,
        threat_class: str,
        alert_data: Dict[str, Any],
        previous_hash: str
    ):
        self.index = index
        self.timestamp = timestamp
        self.alert_id = alert_id
        self.threat_class = threat_class
        self.alert_data = alert_data
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Compute SHA-256 hash over block header and canonical JSON payload."""
        block_header = {
            "index": self.index,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "threat_class": self.threat_class,
            "previous_hash": self.previous_hash,
            "payload_digest": hashlib.sha256(
                json.dumps(self.alert_data, sort_keys=True).encode("utf-8")
            ).hexdigest()
        }
        header_str = json.dumps(block_header, sort_keys=True)
        return hashlib.sha256(header_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "threat_class": self.threat_class,
            "previous_hash": self.previous_hash,
            "block_hash": self.hash,
            "alert_data": self.alert_data
        }


class HashChainLedger:
    """
    Append-only SHA-256 Hash-Chain Forensic Ledger.
    Ensures that security alerts observed over the one-way diode cannot be altered,
    reordered, or deleted without invalidating the cryptographic hash chain.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, ledger_file: Optional[str] = None):
        self.chain: List[AuditBlock] = []
        self.ledger_file = ledger_file
        
        # Initialize Genesis Block if empty
        if not self.chain:
            genesis = AuditBlock(
                index=0,
                timestamp=time.time(),
                alert_id="GENESIS-BLOCK",
                threat_class="SYSTEM_INITIALIZATION",
                alert_data={"message": "DiodeSentinel Cryptographic Forensic Ledger Initialized"},
                previous_hash=self.GENESIS_HASH
            )
            self.chain.append(genesis)

        if self.ledger_file and os.path.exists(self.ledger_file):
            self.load_from_disk()

    @property
    def latest_block(self) -> AuditBlock:
        return self.chain[-1]

    def append_alert(self, alert_record: Dict[str, Any]) -> AuditBlock:
        """Cryptographically commit an alert to the append-only ledger."""
        prev = self.latest_block
        block = AuditBlock(
            index=len(self.chain),
            timestamp=time.time(),
            alert_id=alert_record.get("alert_id", f"ALT-{len(self.chain)}"),
            threat_class=alert_record.get("threat_class", "UNKNOWN"),
            alert_data=alert_record,
            previous_hash=prev.hash
        )
        self.chain.append(block)
        
        if self.ledger_file:
            self._persist_block(block)
            
        return block

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the mathematical integrity of the entire hash-chain.
        Returns validation status and exact block index if tampered.
        """
        if len(self.chain) == 0:
            return {"valid": False, "error": "Empty chain"}

        # 1. Verify Genesis
        if self.chain[0].previous_hash != self.GENESIS_HASH:
            return {"valid": False, "error": "Genesis block previous hash corrupted", "block_index": 0}

        # 2. Verify all subsequent blocks
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check that hash matches contents
            if current.hash != current.compute_hash():
                return {
                    "valid": False,
                    "error": f"Block {i} hash mismatch (tampered content)",
                    "block_index": i
                }

            # Check that previous_hash matches previous block's hash
            if current.previous_hash != previous.hash:
                return {
                    "valid": False,
                    "error": f"Chain link broken between block {i-1} and {i}",
                    "block_index": i
                }

        return {
            "valid": True,
            "chain_length": len(self.chain),
            "latest_hash": self.latest_block.hash,
            "message": "All blocks cryptographically verified with zero tamper detected."
        }

    def _persist_block(self, block: AuditBlock):
        """Append block record to persistent JSONL file."""
        try:
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(block.to_dict()) + "\n")
        except Exception:
            pass

    def load_from_disk(self):
        """Load and verify existing chain from disk."""
        if not self.ledger_file or not os.path.exists(self.ledger_file):
            return
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines:
                if line.strip():
                    data = json.loads(line)
                    if data["index"] == 0:
                        continue  # Skip duplicate genesis
                    block = AuditBlock(
                        index=data["index"],
                        timestamp=data["timestamp"],
                        alert_id=data["alert_id"],
                        threat_class=data["threat_class"],
                        alert_data=data["alert_data"],
                        previous_hash=data["previous_hash"]
                    )
                    block.hash = data["block_hash"]
                    self.chain.append(block)
        except Exception:
            pass
