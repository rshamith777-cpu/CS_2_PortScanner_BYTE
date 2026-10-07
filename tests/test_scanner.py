"""Unit tests for the TCP port scanner engine."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from portscope.models import PortStatus, ScanConfig
from portscope.scanner import PortScanner


class TestPortScanner(unittest.TestCase):
    """Test suite for PortScanner execution and classification logic."""

    def setUp(self):
        self.config = ScanConfig(
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
            ports=[80, 443],
            timeout=0.1,
            workers=2,
        )
        self.scanner = PortScanner(self.config)

    @patch("socket.socket")
    def test_scan_port_open(self, mock_socket_cls):
        """Socket connect_ex returning 0 classifies port as OPEN."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        result = self.scanner.scan_port(80)

        self.assertEqual(result.port, 80)
        self.assertEqual(result.protocol, "tcp")
        self.assertEqual(result.status, PortStatus.OPEN)
        self.assertIsNotNone(result.latency_ms)
        self.assertIsNone(result.error)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_closed(self, mock_socket_cls):
        """Socket connect_ex returning ECONNREFUSED classifies port as CLOSED."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = errno.ECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        result = self.scanner.scan_port(80)

        self.assertEqual(result.port, 80)
        self.assertEqual(result.status, PortStatus.CLOSED)
        self.assertIn("Connection refused", result.error)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_filtered_timeout(self, mock_socket_cls):
        """Socket connect_ex or exception timing out classifies port as FILTERED."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout("Timed out")
        mock_socket_cls.return_value = mock_sock

        result = self.scanner.scan_port(80)

        self.assertEqual(result.port, 80)
        self.assertEqual(result.status, PortStatus.FILTERED)
        self.assertIn("Timed out", result.error)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_filtered_timedout_errno(self, mock_socket_cls):
        """Socket connect_ex returning ETIMEDOUT code classifies as FILTERED."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = errno.ETIMEDOUT
        mock_socket_cls.return_value = mock_sock

        result = self.scanner.scan_port(80)

        self.assertEqual(result.port, 80)
        self.assertEqual(result.status, PortStatus.FILTERED)
        self.assertIn("timed out", result.error.lower())
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scanner_run_deterministic_ordering(self, mock_socket_cls):
        """Full scanner run returns results in strictly sorted port order."""
        mock_sock = MagicMock()
        # Alternate open / closed
        mock_sock.connect_ex.side_effect = [0, errno.ECONNREFUSED]
        mock_socket_cls.return_value = mock_sock

        report = self.scanner.run()

        self.assertEqual(report.metadata.target, "127.0.0.1")
        self.assertEqual(report.metadata.resolved_address, "127.0.0.1")
        self.assertEqual(len(report.results), 2)
        # Port order must be 80 then 443
        self.assertEqual(report.results[0].port, 80)
        self.assertEqual(report.results[1].port, 443)


if __name__ == "__main__":
    unittest.main()
