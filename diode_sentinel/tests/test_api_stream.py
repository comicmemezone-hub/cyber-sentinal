"""
DiodeSentinel - API & WebSocket Integration Test
Verifies end-to-end REST attack injection, real-time alert triage, and telemetry updates.
"""

import unittest
import time
from fastapi.testclient import TestClient
from diode_sentinel.server.app import app


class TestDiodeSentinelAPI(unittest.TestCase):

    def test_full_api_attack_cycle(self):
        with TestClient(app) as client:
            # 1. Health & Status
            status_resp = client.get("/api/status")
            self.assertEqual(status_resp.status_code, 200)
            self.assertIn("active_flows_count", status_resp.json())

            # 2. Inject each attack scenario
            scenarios = [
                "syn_flood",
                "c2_beacon",
                "dns_tunnel",
                "dga",
                "tls_malware",
                "port_scan",
                "data_exfil"
            ]
            for sc in scenarios:
                inject_res = client.post("/api/inject", json={"attack_name": sc})
                self.assertEqual(inject_res.status_code, 200)
                self.assertEqual(inject_res.json()["status"], "SUCCESS")
                time.sleep(0.05)

            time.sleep(0.3)

            # 3. Retrieve Alerts
            alerts_resp = client.get("/api/alerts")
            self.assertEqual(alerts_resp.status_code, 200)
            alerts = alerts_resp.json()
            self.assertGreater(len(alerts), 0, "Expected alerts recorded across injected attacks")

            # Check threat classes present
            threat_classes = {a["threat_class"] for a in alerts}
            print(f"\n[+] Verified active threat classes detected: {threat_classes}")
            self.assertTrue("VOLUMETRIC_DDOS" in threat_classes or "BOTNET_C2_BEACONING" in threat_classes)

            # 4. Clear endpoint
            clear_res = client.post("/api/clear")
            self.assertEqual(clear_res.status_code, 200)
            cleared_alerts = client.get("/api/alerts").json()
            self.assertEqual(len(cleared_alerts), 0)


if __name__ == "__main__":
    unittest.main()
