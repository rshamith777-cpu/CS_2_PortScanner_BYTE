"""Unit tests for port expression parsing."""

import unittest
from portscope.parser import parse_port_expression


class TestPortParser(unittest.TestCase):
    """Test suite for validating and parsing port expressions."""

    def test_single_port(self):
        """Verify parsing of single port."""
        self.assertEqual(parse_port_expression("80"), [80])
        self.assertEqual(parse_port_expression("443"), [443])

    def test_comma_separated_ports(self):
        """Verify parsing of comma separated list."""
        self.assertEqual(parse_port_expression("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_port_expression("  80 , 22 , 443 "), [22, 80, 443])

    def test_port_range(self):
        """Verify parsing of hyphenated port range."""
        self.assertEqual(parse_port_expression("1-5"), [1, 2, 3, 4, 5])
        self.assertEqual(parse_port_expression("8000-8002"), [8000, 8001, 8002])

    def test_mixed_expression(self):
        """Verify mixed single ports and ranges."""
        res = parse_port_expression("22,80,443,8000-8003")
        self.assertEqual(res, [22, 80, 443, 8000, 8001, 8002, 8003])

    def test_duplicate_removal_and_sorting(self):
        """Verify duplicates are stripped and result is sorted in ascending order."""
        res = parse_port_expression("80,22,80,1-3,2")
        self.assertEqual(res, [1, 2, 3, 22, 80])

    def test_empty_expression(self):
        """Verify error raised on empty or whitespace strings."""
        with self.assertRaises(ValueError):
            parse_port_expression("")
        with self.assertRaises(ValueError):
            parse_port_expression("   ")

    def test_invalid_port_values(self):
        """Verify non-numeric and out-of-bound ports raise ValueError."""
        with self.assertRaises(ValueError):
            parse_port_expression("abc")
        with self.assertRaises(ValueError):
            parse_port_expression("0")
        with self.assertRaises(ValueError):
            parse_port_expression("65536")
        with self.assertRaises(ValueError):
            parse_port_expression("-1")

    def test_invalid_ranges(self):
        """Verify malformed and inverted ranges raise ValueError."""
        with self.assertRaises(ValueError):
            parse_port_expression("100-50")
        with self.assertRaises(ValueError):
            parse_port_expression("80-")
        with self.assertRaises(ValueError):
            parse_port_expression("-80")
        with self.assertRaises(ValueError):
            parse_port_expression("80-90-100")
        with self.assertRaises(ValueError):
            parse_port_expression("80-abc")


if __name__ == "__main__":
    unittest.main()
