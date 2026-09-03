"""Build a LABELED evaluation dataset from a benign capture.

We take a real benign flight (a `.tlog` replayed into Events) and insert a real
command-injection event (forced disarm from a rogue sysid) at a known moment in
the flight. Every event is written out tagged `benign` or `attack`, so the eval
harness has exact ground truth to measure recall and false positives against.

This is the standard IDS evaluation technique: known attacks injected into
realistic background traffic, with labels we control.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict

from pymavlink import mavutil

from mavlink_ids.capture.replay import replay_file
from mavlink_ids.parse.decoder import Event

# The attack's signature, matching lab/attacks/inject_disarm.py.
ATTACKER_SYSID = 66
FORCE_MAGIC = 21196
_ARM_DISARM = mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM


def craft_disarm_attack(timestamp: float, sysid: int = ATTACKER_SYSID) -> Event:
    """Build one forced-disarm COMMAND_LONG Event, as the attacker would send it."""
    return Event(
        timestamp=timestamp,
        msg_type="COMMAND_LONG",
        msg_id=76,  # COMMAND_LONG
        sysid=sysid,
        compid=1,
        seq=0,
        signed=False,
        fields={
            "target_system": 1,
            "target_component": 1,
            "command": _ARM_DISARM,
            "confirmation": 0,
            "param1": 0.0,        # 0 = disarm
            "param2": float(FORCE_MAGIC),  # force, bypasses in-flight safety
            "param3": 0.0,
            "param4": 0.0,
            "param5": 0.0,
            "param6": 0.0,
            "param7": 0.0,
        },
    )


def craft_param_tamper(
    timestamp: float,
    sysid: int = ATTACKER_SYSID,
    param_id: str = "FS_THR_ENABLE",
    value: float = 0.0,
) -> Event:
    """Build a PARAM_SET that disables a safety parameter (failsafe tampering).

    Writing 0 to FS_THR_ENABLE turns off the radio-failsafe — so if the link
    later drops, the vehicle will NOT return home or land safely. Silently
    disabling failsafes is a classic pre-attack step.
    """
    return Event(
        timestamp=timestamp,
        msg_type="PARAM_SET",
        msg_id=23,  # PARAM_SET
        sysid=sysid,
        compid=1,
        seq=0,
        signed=False,
        fields={
            "target_system": 1,
            "target_component": 1,
            "param_id": param_id,
            "param_value": value,
            "param_type": mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
        },
    )


def craft_gps_spoof(
    timestamp: float,
    sysid: int = ATTACKER_SYSID,
    lat_deg: float = -35.0,
    lon_deg: float = 138.0,
    alt_m: float = 500.0,
) -> Event:
    """Build a GPS_INPUT with a physically impossible position jump.

    SITL's home is near lat -35.36, lon 149.16. Injecting a fix ~1000 km away
    (lon 138) in a single message is a position jump no real aircraft could make
    — the signature of GPS spoofing. Current rules do NOT catch this: GPS_INPUT
    is telemetry, not a command, so the sysid rule never looks at it.
    """
    return Event(
        timestamp=timestamp,
        msg_type="GPS_INPUT",
        msg_id=232,  # GPS_INPUT
        sysid=sysid,
        compid=1,
        seq=0,
        signed=False,
        fields={
            "time_usec": int(timestamp * 1_000_000),
            "gps_id": 0,
            "ignore_flags": 0,
            "time_week_ms": 0,
            "time_week": 0,
            "fix_type": 3,  # 3D fix
            "lat": int(lat_deg * 1e7),   # degrees * 1e7 (MAVLink integer form)
            "lon": int(lon_deg * 1e7),
            "alt": alt_m,
            "hdop": 1.0,
            "vdop": 1.0,
            "vn": 0.0,
            "ve": 0.0,
            "vd": 0.0,
            "speed_accuracy": 0.0,
            "horiz_accuracy": 0.0,
            "vert_accuracy": 0.0,
            "satellites_visible": 10,
        },
    )


def craft_replay(source: Event, timestamp: float) -> Event:
    """Re-emit an earlier valid packet unchanged — a replay attack.

    The attacker records a legitimate message and re-sends it later. Because the
    bytes are genuine, the source sysid looks trusted and the payload is valid;
    the giveaway is that its sequence number (and content) is a DUPLICATE of one
    already seen. Current rules do not track sequences, so this slips past.
    """
    return Event(
        timestamp=timestamp,        # when the replay is injected
        msg_type=source.msg_type,
        msg_id=source.msg_id,
        sysid=source.sysid,         # same (trusted-looking) source as the original
        compid=source.compid,
        seq=source.seq,             # DUPLICATE sequence number — the tell
        signed=source.signed,
        fields=dict(source.fields),  # identical payload
    )


def build_labeled_dataset(benign_path: str, out_path: str) -> tuple[int, int]:
    """Write a labeled JSONL dataset with four attacks; return (n_benign, n_attack).

    The four attacks are injected at spread-out points in the flight (30%..60%),
    all while the drone is airborne. Every benign event keeps its original
    timestamp; the attacks are inserted at their chosen times and everything is
    re-sorted chronologically so timing/latency math stays meaningful.
    """
    benign = list(replay_file(benign_path))
    if not benign:
        raise ValueError(f"No events decoded from {benign_path!r}.")

    t_start = benign[0].timestamp
    t_end = benign[-1].timestamp

    def at(fraction: float) -> float:
        return t_start + (t_end - t_start) * fraction

    # Pick a real earlier command to replay; fall back to the first event.
    replay_source = next(
        (e for e in benign if e.msg_type == "COMMAND_LONG"), benign[0]
    )

    # (event, attack_type)
    attacks = [
        (craft_disarm_attack(at(0.30)), "command_injection"),
        (craft_param_tamper(at(0.40)), "param_tamper"),
        (craft_gps_spoof(at(0.50)), "gps_spoof"),
        (craft_replay(replay_source, at(0.60)), "replay"),
    ]

    labeled = [(e, "benign", "") for e in benign]
    labeled += [(event, "attack", atype) for event, atype in attacks]
    labeled.sort(key=lambda row: row[0].timestamp)

    with open(out_path, "w", encoding="utf-8") as f:
        for event, label, attack_type in labeled:
            row = asdict(event)
            row["label"] = label
            row["attack_type"] = attack_type
            f.write(json.dumps(row) + "\n")

    return len(benign), len(attacks)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a labeled evaluation dataset from a benign capture."
    )
    parser.add_argument(
        "--benign",
        default="data/benign/benign_flight_01.tlog",
        help="path to a benign .tlog capture",
    )
    parser.add_argument(
        "--out",
        default="data/labeled/attack_disarm_01.jsonl",
        help="path to write the labeled JSONL dataset",
    )
    args = parser.parse_args()

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    n_benign, n_attack = build_labeled_dataset(args.benign, args.out)
    print(
        f"Wrote {n_benign + n_attack} events "
        f"({n_benign} benign, {n_attack} attack) to {args.out}"
    )


if __name__ == "__main__":
    main()
