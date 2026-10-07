"""Input validation and resolution rules for PortScope."""

import ipaddress
import os
import socket
from pathlib import Path
from typing import List, Tuple

from .parser import parse_port_expression

# Valid report output formats
VALID_FORMATS = {"json", "csv"}


def resolve_and_validate_target(target: str) -> str:
    """
    Validate target hostname or IP address and resolve to an IP.

    Ensures target is not empty, does not contain illegal characters,
    and can be resolved safely via standard system DNS/host resolution.

    Returns:
        Resolved IP address string.

    Raises:
        ValueError: If target is malformed or resolution fails.
    """
    if not target or not target.strip():
        raise ValueError("Target host or IP address must not be empty.")

    cleaned_target = target.strip()

    # Reject whitespace or shell-like characters in target
    if any(char in cleaned_target for char in " \t\r\n;|<>&$\"'`"):
        raise ValueError(f"Target '{cleaned_target}' contains illegal characters.")

    # Check if target is already a valid IPv4 or IPv6 address
    try:
        ip_obj = ipaddress.ip_address(cleaned_target)
        return str(ip_obj)
    except ValueError:
        pass

    # Attempt standard hostname DNS resolution
    try:
        resolved_ip = socket.gethostbyname(cleaned_target)
        return resolved_ip
    except socket.gaierror as err:
        raise ValueError(
            f"Could not resolve target hostname '{cleaned_target}': {err}"
        ) from err
    except Exception as err:
        raise ValueError(
            f"Unexpected resolution error for target '{cleaned_target}': {err}"
        ) from err


def validate_ports(port_expression: str) -> List[int]:
    """
    Validate and return parsed list of ports.

    Raises:
        ValueError: When port expression is invalid.
    """
    return parse_port_expression(port_expression)


def validate_timeout(timeout: float) -> float:
    """
    Validate socket timeout duration in seconds.

    Timeout must be positive, typically between 0.05s and 30.0s.
    """
    try:
        val = float(timeout)
    except (ValueError, TypeError):
        raise ValueError("Timeout must be a numeric value in seconds.")

    if val <= 0.0:
        raise ValueError("Timeout must be greater than 0 seconds.")
    if val > 60.0:
        raise ValueError("Timeout exceeds maximum allowed limit of 60.0 seconds.")

    return val


def validate_workers(workers: int) -> int:
    """
    Validate worker thread count for bounded concurrent execution.
    """
    try:
        val = int(workers)
    except (ValueError, TypeError):
        raise ValueError("Worker count must be an integer.")

    if val < 1:
        raise ValueError("Worker count must be at least 1.")
    if val > 100:
        raise ValueError("Worker count cannot exceed 100 to avoid resource exhaustion.")

    return val


def validate_format_and_output(fmt: str, output_path: str = None) -> Tuple[str, Path]:
    """
    Validate output format ('json' or 'csv') and target filepath.

    If output_path is provided, ensures parent directories can be written to.
    """
    cleaned_fmt = fmt.strip().lower()
    if cleaned_fmt not in VALID_FORMATS:
        raise ValueError(f"Invalid format '{fmt}'. Supported formats are: {', '.join(sorted(VALID_FORMATS))}")

    path_obj = None
    if output_path:
        path_obj = Path(output_path).resolve()
        # Verify parent directory exists or can be created
        parent_dir = path_obj.parent
        if not parent_dir.exists():
            try:
                parent_dir.mkdir(parents=True, exist_ok=True)
            except OSError as err:
                raise ValueError(f"Cannot create directory for output file '{output_path}': {err}")

    return cleaned_fmt, path_obj
