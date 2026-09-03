"""Combine detection layers into a single verdict.

The rule engine (Layer 1) and the anomaly detector (Layer 2) each expose a
`.check(event) -> list[Alert]`. This engine runs them all on every event and
unions their alerts: an event is flagged if ANY layer flags it. Rules cover the
known attacks with precision; the anomaly layer covers what they miss.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from mavlink_ids.alert.sink import Alert
from mavlink_ids.parse.decoder import Event


class CombinedEngine:
    """Fan an event out to several detectors and merge their alerts."""

    def __init__(self, *detectors):
        # Each detector needs a .check(event) -> list[Alert] method.
        self._detectors = detectors

    def check(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        for detector in self._detectors:
            alerts.extend(detector.check(event))
        return alerts

    def run(self, events: Iterable[Event], sink=None) -> Iterator[Alert]:
        """Process a stream, optionally emitting each alert to a sink."""
        for event in events:
            for alert in self.check(event):
                if sink is not None:
                    sink.emit(alert)
                yield alert
