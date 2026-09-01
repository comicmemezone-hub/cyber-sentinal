#!/usr/bin/env python3
"""
Cyber Sentinel - Single-Command Hackathon Launcher
Passive Detection of Threats in Unidirectional IP Traffic (Problem ID 26145)

Usage:
  python run.py --web                     # Launch Real-Time SOC Dashboard on http://localhost:8000
  python run.py --pcap datasets/attacks/ddos.pcap  # Ingest & inspect a specific PCAP file
  python run.py --test                    # Run complete 12-test verification suite
"""

import sys
import os
import subprocess
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

if __name__ == "__main__":
    if "--test" in sys.argv:
        print("[+] Running Complete Unit & Integration Test Suite...")
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover(str(ROOT_DIR / "diode_sentinel" / "tests"))
        runner = unittest.TextTestRunner(verbosity=2)
        res = runner.run(suite)
        sys.exit(0 if res.wasSuccessful() else 1)
        
    from diode_sentinel.run_sentinel import main
    main()
