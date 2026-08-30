"""Tests for the Layer 1 rule engine (detect/rules.py).

We build Events by hand — the rules operate on our normalized Event, so no drone,
pymavlink connection, or capture file is needed.
"""

from pymavlink import mavutil

from mavlink_ids.detect.rules import RuleEngine
from mavlink_ids.parse.decoder import Event

ARM_DISARM = mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM


def _disarm_event(sysid: int, param1: float = 0.0, param2: float = 0.0) -> Event:
    """A COMMAND_LONG disarm (param1=0), optionally forced (param2=21196)."""
    return Event(
        timestamp=1.0,
        msg_type="COMMAND_LONG",
        msg_id=76,
        sysid=sysid,
        compid=1,
        seq=0,
        signed=False,
        fields={"command": ARM_DISARM, "param1": param1, "param2": param2},
    )


def _telemetry_event(sysid: int = 1) -> Event:
    """A passive ATTITUDE telemetry message — nothing suspicious."""
    return Event(
        timestamp=1.0,
        msg_type="ATTITUDE",
        msg_id=30,
        sysid=sysid,
        compid=1,
        seq=0,
        signed=False,
        fields={"roll": 0.0, "pitch": 0.0, "yaw": 0.0},
    )


def test_forced_disarm_from_rogue_sysid_is_critical():
    # This is exactly the attack: forced disarm injected under sysid 66.
    alerts = RuleEngine().check(_disarm_event(sysid=66, param2=21196))

    fired = {a.rule for a in alerts}
    assert "unexpected_sysid" in fired   # rogue source caught
    assert "forced_disarm" in fired      # dangerous action caught
    assert all(a.severity == "critical" for a in alerts)


def test_benign_telemetry_raises_no_alerts():
    # A noisy IDS is a useless IDS: normal telemetry must stay silent.
    assert RuleEngine().check(_telemetry_event(sysid=1)) == []


def test_normal_disarm_from_trusted_gcs_is_warning_only():
    # Disarm from the real GCS (255), no force flag: a warning, not a critical,
    # and the sysid rule must NOT fire (255 is trusted).
    alerts = RuleEngine().check(_disarm_event(sysid=255, param2=0))

    assert {a.rule for a in alerts} == {"disarm_command"}
    assert alerts[0].severity == "warning"
