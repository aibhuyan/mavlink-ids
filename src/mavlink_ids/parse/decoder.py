"""Decode raw MAVLink messages into normalized Event records.

MAVLink on the wire is a binary protocol: message id, sequence number, system
and component ids, packed fields, and a checksum. `pymavlink` already decodes
those bytes into message objects. This module's job is the *next* step: flatten
each message into a single uniform `Event` shape that the rest of the IDS
(features, rules, anomaly model) can read without knowing MAVLink internals.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    """One MAVLink message, normalized to the fields our detector cares about.

    Every attack in the threat model shows up as some combination of *who*
    sent a message (`sysid`/`compid`), *what* it was (`msg_type`), *when*
    (`timestamp`), *whether it was authenticated* (`signed`), and the message's
    own payload (`fields`). Keeping one flat record for all message types lets
    the detection layers treat traffic uniformly.
    """

    timestamp: float          # when we observed the message (seconds)
    msg_type: str             # human name, e.g. "HEARTBEAT", "COMMAND_LONG"
    msg_id: int               # numeric MAVLink message id
    sysid: int                # source system id (which vehicle/GCS sent it)
    compid: int               # source component id (which part of that system)
    seq: int                  # per-link sequence number (0-255, wraps around)
    signed: bool              # True if the packet carried a valid v2 signature
    fields: dict[str, Any] = field(default_factory=dict)  # decoded payload


def to_event(msg: Any) -> Event:
    """Convert one decoded pymavlink message into a normalized `Event`.

    `msg` is whatever `pymavlink` hands back from parsing (a MAVLink_message
    object). We pull the metadata off it with pymavlink's accessor methods and
    copy the payload out of `to_dict()`. Callers should skip "BAD_DATA"
    messages (undecodable bytes) before calling this.
    """
    # to_dict() includes a "mavpackettype" key that just repeats the type name;
    # drop it so `fields` holds only the real payload.
    payload = msg.to_dict()
    payload.pop("mavpackettype", None)

    # pymavlink stamps each message with the time it was parsed. Fall back to
    # "now" if it is missing (some synthetic messages have no timestamp).
    timestamp = getattr(msg, "_timestamp", None) or time.time()

    return Event(
        timestamp=timestamp,
        msg_type=msg.get_type(),
        msg_id=msg.get_msgId(),
        sysid=msg.get_srcSystem(),
        compid=msg.get_srcComponent(),
        seq=msg.get_seq(),
        signed=bool(msg.get_signed()),
        fields=payload,
    )


def decode_stream(conn: Any) -> Iterator[Event]:
    """Yield a stream of normalized `Event`s from a pymavlink connection.

    `conn` is a pymavlink connection (from `mavutil.mavlink_connection`), which
    can wrap either a live UDP link or a replayed capture file — the parser does
    not care which. We read one message at a time and hand back Events, skipping
    "BAD_DATA" (bytes pymavlink could not decode).

    This is a generator: it produces events lazily, one per loop, instead of
    building a giant list in memory. For a live link it keeps yielding until the
    process is stopped; for a replay file it stops at the end of the file.
    """
    while True:
        msg = conn.recv_match(blocking=True)
        if msg is None:
            break  # connection closed or end of a replay file
        if msg.get_type() == "BAD_DATA":
            continue  # undecodable bytes — not a real message
        yield to_event(msg)
