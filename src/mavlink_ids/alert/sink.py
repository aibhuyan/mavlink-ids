"""Alerts: the finding a detector emits, plus where those findings go.

A good IDS alert is *explainable* — a security operator must see, at a glance,
what fired, how serious it is, and why. So an `Alert` carries a rule name, a
severity, a plain-language reason, and enough of the offending event to act on.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, TextIO

# Severity levels, lowest to highest. Kept as plain strings for readable output.
SEVERITIES = ("info", "warning", "critical")


@dataclass
class Alert:
    """One detector finding about one suspicious event."""

    timestamp: float          # time of the offending event (seconds)
    severity: str             # one of SEVERITIES
    rule: str                 # short id of the rule that fired, e.g. "unexpected_sysid"
    message: str              # plain-language reason a human can act on
    sysid: int                # source system id of the offending event
    msg_type: str             # MAVLink type of the offending event
    context: dict[str, Any] = field(default_factory=dict)  # extra detail, optional


def format_line(alert: Alert) -> str:
    """Render an alert as one readable console line."""
    return (
        f"[{alert.severity.upper():8}] {alert.rule}: {alert.message} "
        f"(sysid={alert.sysid}, msg={alert.msg_type}, t={alert.timestamp:.3f})"
    )


class ConsoleSink:
    """Print alerts to the console (or any text stream) as readable lines."""

    def __init__(self, stream: TextIO | None = None):
        # Default to stdout, but allow injecting a stream (handy for tests).
        self._stream = stream

    def emit(self, alert: Alert) -> None:
        print(format_line(alert), file=self._stream)


class JsonlSink:
    """Append alerts to a file as JSON Lines (one JSON object per line).

    JSONL is easy to produce incrementally and easy for the eval harness or a
    dashboard to read back, one alert at a time.
    """

    def __init__(self, path: str):
        self._file = open(path, "a", encoding="utf-8")

    def emit(self, alert: Alert) -> None:
        self._file.write(json.dumps(asdict(alert)) + "\n")
        self._file.flush()  # write through immediately so alerts aren't lost

    def close(self) -> None:
        self._file.close()
