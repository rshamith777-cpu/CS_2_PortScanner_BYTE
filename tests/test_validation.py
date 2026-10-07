"""Unit tests for input validation routines."""

import socket
import unittest
from pathlib import Path
from unittest.mock import patch

from portscope.validation import (
    resolve_and_validate_target,
    validate_format_and_output,
    validate_ports,
    validate_timeout,
    validate_workers,
)


class TestValidation(unittest.TestCase):
    """Test suite for CLI input validation and safety checks."""

    def test_valid_ipv4_target(self):
        """Valid IPv4 targets resolve directly without DNS lookups."""
        self.assertEqual(resolve_and_validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(resolve_and_validate_target("192.168.1.1"), "192.168.1.1")

    def test_localhost_hostname_resolution(self):
        """Localhost resolves to loopback IP address."""
        resolved = resolve_and_validate_target("localhost")
        self.assertIn(resolved, ["127.0.0.1", "::1"])

    def test_empty_target(self):
        """Empty target raises ValueError."""
        with self.assertRaises(ValueError):
            resolve_and_validate_target("")
        with self.assertRaises(ValueError):
            resolve_and_validate_target("   ")

    def test_illegal_target_characters(self):
        """Special injection characters are rejected."""
        with self.assertRaises(ValueError):
            resolve_and_validate_target("127.0.0.1; rm -rf /")
        with self.assertRaises(ValueError):
            resolve_and_validate_target("localhost && ping 8.8.8.8")

    @patch("socket.gethostbyname", side_effect=socket.gaierror("Name or service not known"))
    def test_unresolvable_target(self, mock_dns):
        """Unresolvable hostname raises user-friendly ValueError."""
        with self.assertRaises(ValueError) as ctx:
            resolve_and_validate_target("nonexistent.invalid.example.test")
        self.assertIn("Could not resolve target hostname", str(ctx.exception))

    def test_validate_timeout(self):
        """Verify timeout validation boundaries."""
        self.assertEqual(validate_timeout(1.5), 1.5)
        self.assertEqual(validate_timeout("2.0"), 2.0)

        with self.assertRaises(ValueError):
            validate_timeout(0.0)
        with self.assertRaises(ValueError):
            validate_timeout(-1)
        with self.assertRaises(ValueError):
            validate_timeout(70.0)  # > 60s
        with self.assertRaises(ValueError):
            validate_timeout("invalid")

    def test_validate_workers(self):
        """Verify worker count constraints."""
        self.assertEqual(validate_workers(10), 10)
        self.assertEqual(validate_workers("25"), 25)

        with self.assertRaises(ValueError):
            validate_workers(0)
        with self.assertRaises(ValueError):
            validate_workers(-5)
        with self.assertRaises(ValueError):
            validate_workers(101)  # > 100
        with self.assertRaises(ValueError):
            validate_workers("invalid")

    def test_validate_format_and_output(self):
        """Verify output format acceptance and directory preparation."""
        fmt, path = validate_format_and_output("json", None)
        self.assertEqual(fmt, "json")
        self.assertIsNone(path)

        fmt, path = validate_format_and_output("CSV", "test_report.csv")
        self.assertEqual(fmt, "csv")
        self.assertIsInstance(path, Path)

        with self.assertRaises(ValueError):
            validate_format_and_output("xml", None)


if __name__ == "__main__":
    unittest.main()
