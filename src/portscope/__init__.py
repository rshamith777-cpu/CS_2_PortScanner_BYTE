"""PortScope: A modular Python TCP port scanner for authorized security testing."""

__version__ = "0.1.0"
__author__ = "AVIP CyberSecurity Intern"

from .models import PortResult, PortStatus, ScanConfig, ScanMetadata, ScanReport
from .scanner import PortScanner

__all__ = [
    "PortResult",
    "PortStatus",
    "ScanConfig",
    "ScanMetadata",
    "ScanReport",
    "PortScanner",
]
