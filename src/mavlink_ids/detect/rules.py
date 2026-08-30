"""Layer 1: signature / rule engine.

Deterministic, high-precision, explainable checks over the Event stream. Each
rule looks at an event (and, later, a little state) and returns an `Alert` when a
known-bad pattern appears. Rules catch the *known* attacks and, crucially, give a
human a readable reason — the thing a security operator actually needs.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from pymavlink import mavutil

from mavlink_ids.alert.sink import Alert
from mavlink_ids.parse.decoder import Event

# MAVLink message types that carry commands/control (not passive telemetry).
# A stranger sending any of these is far more suspicious than one appearing in
# read-only telemetry, so we scope the sysid check to these.
COMMAND_TYPES = frozenset(
    {
        "COMMAND_LONG",
        "COMMAND_INT",
        "SET_MODE",
        "PARAM_SET",
        "MISSION_ITEM",
        "MISSION_ITEM_INT",
        "MISSION_SET_CURRENT",
        "MISSION_COUNT",
        "RC_CHANNELS_OVERRIDE",
    }
)

# System ids we trust on this link: the vehicle (1) and the legitimate GCS (255).
DEFAULT_ALLOWED_SYSIDS = frozenset({1, 255})

# The disarm command, and the magic param2 value that FORCES it (bypassing the
# safety check that normally refuses a disarm while airborne).
_ARM_DISARM = mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM
_FORCE_MAGIC = 21196


class RuleEngine:
    """Runs the signature rules over events and produces alerts."""

    def __init__(self, allowed_sysids: Iterable[int] = DEFAULT_ALLOWED_SYSIDS):
        self.allowed_sysids = set(allowed_sysids)
        # The rules to run, in order.
        self._rules = (self._rule_unexpected_sysid, self._rule_forced_disarm)

    def check(self, event: Event) -> list[Alert]:
        """Run every rule on one event; return any alerts they raise."""
        alerts = []
        for rule in self._rules:
            alert = rule(event)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def run(self, events: Iterable[Event], sink=None) -> Iterator[Alert]:
        """Process a stream of events, optionally emitting alerts to a sink."""
        for event in events:
            for alert in self.check(event):
                if sink is not None:
                    sink.emit(alert)
                yield alert

    # --- rules ---------------------------------------------------------------

    def _rule_unexpected_sysid(self, event: Event) -> Alert | None:
        """Flag a command sent by a system id we don't trust (a rogue GCS)."""
        if event.msg_type not in COMMAND_TYPES:
            return None
        if event.sysid in self.allowed_sysids:
            return None
        return Alert(
            timestamp=event.timestamp,
            severity="critical",
            rule="unexpected_sysid",
            message=(
                f"Command {event.msg_type} from unexpected sysid {event.sysid} "
                f"(trusted: {sorted(self.allowed_sysids)})"
            ),
            sysid=event.sysid,
            msg_type=event.msg_type,
            context={"allowed_sysids": sorted(self.allowed_sysids)},
        )

    def _rule_forced_disarm(self, event: Event) -> Alert | None:
        """Flag a disarm command; critical if it carries the FORCE flag."""
        if event.msg_type != "COMMAND_LONG":
            return None
        if event.fields.get("command") != _ARM_DISARM:
            return None
        # param1: 1.0 = arm, 0.0 = disarm. We only care about disarm here.
        if event.fields.get("param1", 1) != 0:
            return None

        forced = event.fields.get("param2") == _FORCE_MAGIC
        return Alert(
            timestamp=event.timestamp,
            severity="critical" if forced else "warning",
            rule="forced_disarm" if forced else "disarm_command",
            message=(
                f"{'Forced disarm' if forced else 'Disarm'} command from sysid "
                f"{event.sysid}"
                + (" with FORCE flag — bypasses the in-flight safety check"
                   if forced else "")
            ),
            sysid=event.sysid,
            msg_type=event.msg_type,
            context={
                "param1": event.fields.get("param1"),
                "param2": event.fields.get("param2"),
            },
        )
