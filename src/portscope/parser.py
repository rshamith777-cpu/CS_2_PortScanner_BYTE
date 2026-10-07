"""Port range and target expression parsing logic for PortScope."""

import re
from typing import List, Set


def parse_port_expression(expression: str) -> List[int]:
    """
    Parse a comma-separated list of individual ports and/or port ranges.

    Examples of valid input:
        - "80"
        - "22,80,443"
        - "1-100"
        - "22,80,443,8000-8010"

    Returns:
        Sorted list of unique integer port numbers.

    Raises:
        ValueError: If expression is malformed, empty, or outside port range 1-65535.
    """
    if not expression or not expression.strip():
        raise ValueError("Port expression cannot be empty.")

    cleaned_expr = expression.strip()
    tokens = [t.strip() for t in cleaned_expr.split(",") if t.strip()]

    if not tokens:
        raise ValueError("No valid port tokens found in expression.")

    parsed_ports: Set[int] = set()

    for token in tokens:
        # Check if token is a range: "start-end"
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(f"Malformed port range: '{token}'. Must have format 'start-end'.")

            start_str, end_str = parts[0].strip(), parts[1].strip()

            if not start_str.isdigit() or not end_str.isdigit():
                raise ValueError(f"Non-numeric values in port range: '{token}'.")

            start, end = int(start_str), int(end_str)

            if start < 1 or start > 65535:
                raise ValueError(f"Port range start {start} is out of bounds (1-65535).")
            if end < 1 or end > 65535:
                raise ValueError(f"Port range end {end} is out of bounds (1-65535).")
            if start > end:
                raise ValueError(f"Invalid range '{token}': start port {start} is greater than end port {end}.")

            for port in range(start, end + 1):
                parsed_ports.add(port)
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port value: '{token}'. Must be an integer between 1 and 65535.")

            port = int(token)
            if port < 1 or port > 65535:
                raise ValueError(f"Port {port} is out of bounds. Must be between 1 and 65535.")

            parsed_ports.add(port)

    if not parsed_ports:
        raise ValueError("No valid ports parsed from expression.")

    return sorted(list(parsed_ports))
