"""Data models for PortScope scan requests and results."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PortStatus(str, Enum):
    """Classification of port status from TCP connect attempt."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass(frozen=True)
class ScanConfig:
    """Configuration options for a scan operation."""
    target: str
    resolved_ip: str
    ports: List[int]
    timeout: float = 1.0
    workers: int = 10


@dataclass
class PortResult:
    """Result of scanning an individual TCP port."""
    port: int
    protocol: str = "tcp"
    status: PortStatus = PortStatus.FILTERED
    latency_ms: Optional[float] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "error": self.error,
        }


@dataclass
class ScanMetadata:
    """Metadata detailing the execution of a port scan."""
    timestamp: str
    target: str
    resolved_address: str
    timeout_seconds: float
    port_count: int
    duration_ms: float
    workers: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "resolved_address": self.resolved_address,
            "timeout_seconds": self.timeout_seconds,
            "port_count": self.port_count,
            "duration_ms": round(self.duration_ms, 2),
            "workers": self.workers,
        }


@dataclass
class ScanReport:
    """Full scan report encompassing metadata and port results."""
    metadata: ScanMetadata
    results: List[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.status == PortStatus.OPEN]

    @property
    def closed_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.status == PortStatus.CLOSED]

    @property
    def filtered_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.status == PortStatus.FILTERED]

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan report to dictionary representation for serialization."""
        return {
            "scan_metadata": self.metadata.to_dict(),
            "summary": {
                "total_scanned": self.metadata.port_count,
                "open_count": len(self.open_ports),
                "closed_count": len(self.closed_ports),
                "filtered_count": len(self.filtered_ports),
            },
            "results": [r.to_dict() for r in self.results],
        }
