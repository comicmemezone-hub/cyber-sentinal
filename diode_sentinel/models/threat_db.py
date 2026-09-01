"""
DiodeSentinel - Threat Intelligence Signature Database
Pre-indexed database of JA3/JA3S fingerprints, malware profiles, and DGA seeds
"""

# High-fidelity Malicious JA3 Hashes curated from Abuse.ch / SSLBL / Mandiant / Threat Fox
KNOWN_MALICIOUS_JA3 = {
    # Cobalt Strike Beacon
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "family": "Cobalt Strike",
        "category": "C2 Framework",
        "severity": "CRITICAL",
        "description": "Standard Cobalt Strike HTTPS Beacon Client Hello profile"
    },
    "72a589da586844d7f0818ce684948eea": {
        "family": "Cobalt Strike",
        "category": "C2 Framework",
        "severity": "CRITICAL",
        "description": "Malleable C2 HTTPS profile with TLS 1.2 custom ciphers"
    },
    # Emotet Banking Trojan / Loader
    "4d7a28d6f22da2d5ee1e847c20c0fef5": {
        "family": "Emotet",
        "category": "Trojan / Loader",
        "severity": "CRITICAL",
        "description": "Emotet epoch 4/5 TLS fingerprint"
    },
    "51c64c77e60f3980eea90869b68c58a8": {
        "family": "Emotet",
        "category": "Trojan / Loader",
        "severity": "CRITICAL",
        "description": "Emotet automated payload delivery session"
    },
    # AsyncRAT / QuasarRAT
    "b32309a26951912be7dba376398abc3b": {
        "family": "AsyncRAT",
        "category": "Remote Access Trojan",
        "severity": "HIGH",
        "description": "AsyncRAT encrypted client handshake"
    },
    "0cce74b0192826862683fb10e566b874": {
        "family": "QuasarRAT",
        "category": "Remote Access Trojan",
        "severity": "HIGH",
        "description": "QuasarRAT TLS 1.3 telemetry"
    },
    # RedLine Stealer
    "6734f37431670b3ab4292b8f60f29984": {
        "family": "RedLine Stealer",
        "category": "Infostealer",
        "severity": "CRITICAL",
        "description": "RedLine Stealer exfiltration channel"
    },
    # Dridex
    "9dc13f64c6cdb947c94b7f8cbf5db405": {
        "family": "Dridex",
        "category": "Banking Trojan",
        "severity": "CRITICAL",
        "description": "Dridex botnet affiliate TLS profile"
    },
    # TrickBot
    "c5e7b233a1e4d01b1b369165d4911d9f": {
        "family": "TrickBot",
        "category": "Modular Trojan / Ransomware Precursor",
        "severity": "CRITICAL",
        "description": "TrickBot anchor TLS beaconing"
    },
    # Metasploit Meterpreter
    "c12f54070a316279f0413155eb19d453": {
        "family": "Metasploit Meterpreter",
        "category": "Exploitation Tool",
        "severity": "HIGH",
        "description": "Reverse HTTPS default Meterpreter payload"
    }
}

# Known Safe / Standard JA3 Hashes (Browsers, OS services)
KNOWN_BENIGN_JA3 = {
    "b32309a26951912be7dba376398abc10": "Google Chrome (Windows)",
    "eb1d94de9e3f310f6372e1d555777700": "Mozilla Firefox (Linux)",
    "cd08e31494f9531f560d64c695473da9": "Apple Safari (macOS)",
    "66918128f1b9b03303d77c6f2eefd128": "Windows Update Agent",
    "3b5074b1b082e00e1473ec77b85f4300": "Microsoft Teams / Edge"
}

# Known DGA Wordlist/Patterns
DGA_KNOWN_PATTERNS = [
    r"^[a-z0-9]{16,32}\.(biz|info|top|xyz|cc|su|ru)$",
    r"^[bcdfghjklmnpqrstvwxyz]{8,}\.(com|net|org)$",
    r"^[0-9a-f]{20,}\.",  # Hex encoded subdomains
    r"^[A-Za-z0-9+/=]{24,}\."  # Base64 encoded subdomains
]

def lookup_ja3(ja3_hash: str) -> dict | None:
    """Lookup a JA3 hash in the threat intelligence database."""
    if not ja3_hash:
        return None
    return KNOWN_MALICIOUS_JA3.get(ja3_hash.lower())

def is_benign_ja3(ja3_hash: str) -> bool:
    """Check if JA3 is a known legitimate browser or OS agent."""
    if not ja3_hash:
        return False
    return ja3_hash.lower() in KNOWN_BENIGN_JA3
