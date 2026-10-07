"""Core TCP scanning engine for PortScope."""

import concurrent.futures
import errno
import socket
import time
from datetime import datetime, timezone
from typing import Callable, List, Optional

from .models import PortResult, PortStatus, ScanConfig, ScanMetadata, ScanReport


class PortScanner:
    """
    Executes standard TCP connect scans against authorized target IP addresses.

    Safety:
    - Uses regular standard library TCP connect sockets.
    - No raw packet crafting or evasion techniques.
    - Bounded ThreadPoolExecutor for deterministic concurrent checks.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    def scan_port(self, port: int) -> PortResult:
        """
        Scan a single TCP port using standard socket connect.

        Classification Logic:
        - OPEN: Socket connect returns 0 (handshake succeeded).
        - CLOSED: Connection actively refused (WSAECONNREFUSED / ECONNREFUSED).
        - FILTERED: Connection timed out (socket.timeout / WSAETIMEDOUT) or
                    network/host unreachable.
        """
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)

        try:
            # Attempt standard TCP 3-way handshake
            result_code = sock.connect_ex((self.config.resolved_ip, port))
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if result_code == 0:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    status=PortStatus.OPEN,
                    latency_ms=elapsed_ms,
                    error=None,
                )

            # Common OS socket error codes for refused connections
            # On Windows: errno.WSAECONNREFUSED (10061), on Unix: errno.ECONNREFUSED (111)
            refused_codes = {errno.ECONNREFUSED}
            if hasattr(errno, "WSAECONNREFUSED"):
                refused_codes.add(errno.WSAECONNREFUSED)

            # Timed out error codes
            timeout_codes = {errno.ETIMEDOUT}
            if hasattr(errno, "WSAETIMEDOUT"):
                timeout_codes.add(errno.WSAETIMEDOUT)

            if result_code in refused_codes:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    status=PortStatus.CLOSED,
                    latency_ms=elapsed_ms,
                    error=f"Connection refused (code {result_code})",
                )
            elif result_code in timeout_codes:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    status=PortStatus.FILTERED,
                    latency_ms=elapsed_ms,
                    error=f"Connection timed out (code {result_code})",
                )
            else:
                # Other socket codes (e.g., host unreachable, network unreachable, permission)
                return PortResult(
                    port=port,
                    protocol="tcp",
                    status=PortStatus.FILTERED,
                    latency_ms=elapsed_ms,
                    error=f"System error code {result_code}",
                )

        except socket.timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return PortResult(
                port=port,
                protocol="tcp",
                status=PortStatus.FILTERED,
                latency_ms=elapsed_ms,
                error="Timed out waiting for response",
            )
        except OSError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            # Check for Windows or Unix connection refused in exception errno
            if exc.errno in {getattr(errno, "WSAECONNREFUSED", -1), errno.ECONNREFUSED}:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    status=PortStatus.CLOSED,
                    latency_ms=elapsed_ms,
                    error=f"Connection refused ({exc})",
                )
            return PortResult(
                port=port,
                protocol="tcp",
                status=PortStatus.FILTERED,
                latency_ms=elapsed_ms,
                error=str(exc),
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def run(self, progress_callback: Optional[Callable[[PortResult], None]] = None) -> ScanReport:
        """
        Execute the port scan across all configured ports using bounded concurrency.

        Results are guaranteed to be returned in strictly sorted port order.
        """
        scan_start_utc = datetime.now(timezone.utc).isoformat()
        total_start_time = time.perf_counter()

        results: List[PortResult] = []
        max_workers = max(1, min(self.config.workers, len(self.config.ports)))

        if max_workers == 1:
            for port in self.config.ports:
                res = self.scan_port(port)
                results.append(res)
                if progress_callback:
                    progress_callback(res)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, port): port
                    for port in self.config.ports
                }
                for future in concurrent.futures.as_completed(future_to_port):
                    res = future.result()
                    results.append(res)
                    if progress_callback:
                        progress_callback(res)

        # Sort deterministically by port number
        results.sort(key=lambda r: r.port)

        total_elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0

        metadata = ScanMetadata(
            timestamp=scan_start_utc,
            target=self.config.target,
            resolved_address=self.config.resolved_ip,
            timeout_seconds=self.config.timeout,
            port_count=len(self.config.ports),
            duration_ms=total_elapsed_ms,
            workers=max_workers,
        )

        return ScanReport(metadata=metadata, results=results)
