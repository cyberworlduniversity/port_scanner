import unittest
from port_scanner import validate_scan_options, validate_scan_target


class PortScannerSafetyTests(unittest.TestCase):
    def test_private_ipv4_is_allowed(self):
        self.assertEqual(validate_scan_target("192.168.1.10"), "192.168.1.10")

    def test_public_ipv4_requires_explicit_permission(self):
        with self.assertRaises(ValueError):
            validate_scan_target("8.8.8.8")
        self.assertEqual(validate_scan_target("8.8.8.8", allow_public=True), "8.8.8.8")

    def test_special_and_invalid_addresses_are_rejected(self):
        for target in ("127.0.0.1", "169.254.169.254", "224.0.0.1", "not-an-ip", "::1"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_scan_target(target, allow_public=True)

    def test_scan_resource_limits(self):
        validate_scan_options(1, 1024, 100, 0.5)
        for args in ((1, 2048, 10, 0.5), (1, 65536, 10, 0.5), (1, 10, 101, 0.5), (1, 10, 2, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                validate_scan_options(*args)


if __name__ == "__main__":
    unittest.main()
