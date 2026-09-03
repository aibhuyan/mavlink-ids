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


def build_labeled_dataset(
    benign_path: str, out_path: str, attack_fraction: float = 0.5
) -> tuple[int, int]:
    """Write a labeled JSONL dataset; return (n_benign, n_attack).

    `attack_fraction` places the injection along the flight timeline: 0.5 means
    halfway through, when the drone is airborne. Every benign event keeps its
    original timestamp; the attack is inserted at that point and everything is
    re-sorted by time so the stream reads chronologically.
    """
    benign = list(replay_file(benign_path))
    if not benign:
        raise ValueError(f"No events decoded from {benign_path!r}.")

    t_start = benign[0].timestamp
    t_end = benign[-1].timestamp
    attack_time = t_start + (t_end - t_start) * attack_fraction

    # (event, label, attack_type)
    labeled = [(e, "benign", "") for e in benign]
    labeled.append((craft_disarm_attack(attack_time), "attack", "command_injection"))
    labeled.sort(key=lambda row: row[0].timestamp)

    with open(out_path, "w", encoding="utf-8") as f:
        for event, label, attack_type in labeled:
            row = asdict(event)
            row["label"] = label
            row["attack_type"] = attack_type
            f.write(json.dumps(row) + "\n")

    n_attack = sum(1 for _, label, _ in labeled if label == "attack")
    return len(benign), n_attack


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
    parser.add_argument(
        "--attack-fraction",
        type=float,
        default=0.5,
        help="where in the flight to inject the attack (0.0=start, 1.0=end)",
    )
    args = parser.parse_args()

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    n_benign, n_attack = build_labeled_dataset(
        args.benign, args.out, args.attack_fraction
    )
    print(
        f"Wrote {n_benign + n_attack} events "
        f"({n_benign} benign, {n_attack} attack) to {args.out}"
    )


if __name__ == "__main__":
    main()
