"""Replay a saved MAVLink capture as a stream of normalized Events.

A `.tlog` (telemetry log, written by MAVProxy/QGroundControl) is just MAVLink
messages on disk, each prefixed with the time it was received. Replaying one
gives us the exact same event stream a live link would — but repeatable, offline,
and on any machine. That reproducibility is what the evaluation phase needs.
"""

from __future__ import annotations

from collections.abc import Iterator

from pymavlink import mavutil

from mavlink_ids.parse.decoder import Event, decode_stream


def replay_file(path: str) -> Iterator[Event]:
    """Yield the Events recorded in a capture file at `path`.

    pymavlink recognises the `.tlog` format from the filename and reads back each
    message together with its original timestamp. We hand that connection to
    `decode_stream` in non-blocking mode so it stops cleanly at end-of-file.
    """
    conn = mavutil.mavlink_connection(path)
    try:
        yield from decode_stream(conn, blocking=False)
    finally:
        conn.close()
