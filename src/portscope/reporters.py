"""Structured report exporters (JSON and CSV) for PortScope."""

import csv
import json
from pathlib import Path
from typing import Union

from .models import ScanReport


def export_json(report: ScanReport, destination: Union[str, Path]) -> str:
    """
    Export scan results to a formatted JSON report.

    Args:
        report: Completed ScanReport object.
        destination: File path or Path object.

    Returns:
        Absolute string path to written file.
    """
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = report.to_dict()

    with open(path, mode="w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return str(path.resolve())


def export_csv(report: ScanReport, destination: Union[str, Path]) -> str:
    """
    Export scan results to a structured CSV report.

    Header schema:
    timestamp,target,resolved_address,port,protocol,status,latency_ms,error

    Args:
        report: Completed ScanReport object.
        destination: File path or Path object.

    Returns:
        Absolute string path to written file.
    """
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)

    headers = [
        "timestamp",
        "target",
        "resolved_address",
        "port",
        "protocol",
        "status",
        "latency_ms",
        "error",
    ]

    with open(path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

        for res in report.results:
            writer.writerow({
                "timestamp": report.metadata.timestamp,
                "target": report.metadata.target,
                "resolved_address": report.metadata.resolved_address,
                "port": res.port,
                "protocol": res.protocol,
                "status": res.status.value,
                "latency_ms": round(res.latency_ms, 2) if res.latency_ms is not None else "",
                "error": res.error or "",
            })

    return str(path.resolve())
