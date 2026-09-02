import unittest

from scanner.discovery import validate_private_network
from scanner.risk_analyzer import analyze_ports
from scanner.services import service_name


class ScannerTests(unittest.TestCase):
    def test_accepts_private_network(self):
        self.assertEqual(str(validate_private_network("192.168.1.10/24")), "192.168.1.0/24")

    def test_rejects_unsafe_networks(self):
        for network in ("8.8.8.0/24", "192.168.0.0/16", "invalid"):
            with self.subTest(network=network), self.assertRaises(ValueError):
                validate_private_network(network)

    def test_telnet_requires_review(self):
        status, findings = analyze_ports([23, 80])
        self.assertEqual(status, "Revisar")
        self.assertTrue(findings)

    def test_known_service(self):
        self.assertEqual(service_name(443), "HTTPS")


if __name__ == "__main__":
    unittest.main()
