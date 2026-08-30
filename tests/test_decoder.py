"""Tests for the MAVLink parser (parse/decoder.py).

These run entirely offline: we build a real MAVLink message in memory with
pymavlink, feed it through our decoder, and check the resulting Event. No SITL,
no network, no capture file needed.
"""

from pymavlink import mavutil

from mavlink_ids.parse.decoder import Event, decode_stream, to_event


def _make_heartbeat(sysid: int = 7, compid: int = 1):
    """Encode a HEARTBEAT, then decode it back — mimics a real received message."""
    mav = mavutil.mavlink.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    msg = mav.heartbeat_encode(
        mavutil.mavlink.MAV_TYPE_QUADROTOR,
        mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
        base_mode=0,
        custom_mode=0,
        system_status=mavutil.mavlink.MAV_STATE_ACTIVE,
    )
    raw = msg.pack(mav)              # turn the message into wire bytes (assigns seq)
    return mav.decode(bytearray(raw))  # decode() mutates the buffer, so give it a bytearray


def test_to_event_extracts_metadata():
    parsed = _make_heartbeat(sysid=7, compid=1)

    event = to_event(parsed)

    assert isinstance(event, Event)
    assert event.msg_type == "HEARTBEAT"
    assert event.sysid == 7
    assert event.compid == 1
    assert event.timestamp > 0
    # payload is present, and the noise key was stripped
    assert "type" in event.fields
    assert "mavpackettype" not in event.fields


class _StubMessage:
    """Minimal stand-in for a pymavlink message that only knows its type."""

    def __init__(self, type_name: str):
        self._type_name = type_name

    def get_type(self) -> str:
        return self._type_name


class _FakeConn:
    """A fake pymavlink connection: hands back a fixed list, then None (EOF)."""

    def __init__(self, messages):
        self._iter = iter(messages)

    def recv_match(self, blocking: bool = False):
        return next(self._iter, None)


def test_decode_stream_skips_bad_data():
    conn = _FakeConn([_make_heartbeat(), _StubMessage("BAD_DATA")])

    events = list(decode_stream(conn))

    # Only the real HEARTBEAT survives; BAD_DATA is dropped.
    assert len(events) == 1
    assert events[0].msg_type == "HEARTBEAT"
