# MAVLink IDS — Intrusion Detection for Drone Command & Control

A passive, software-only **intrusion-detection system** for the MAVLink protocol
that drones speak to their ground stations. It watches the command-and-control
(C2) link between a Ground Control Station and a **simulated** drone
(ArduPilot SITL), and flags malicious or anomalous commands — command injection,
spoofing, replay, denial-of-service — in real time, with an explainable reason
for every alert.

> **Status:** Build phase complete — MAVLink parser, simulation lab, a red-team
> attack, and an explainable rule engine that catches a live command-injection
> with **zero false positives** on a real benign flight. Proving phase (full
> labeled dataset, measured metrics, and an ML anomaly layer) in progress.

> **Safety:** Everything is passive, simulated, and localhost-only. Nothing
> transmits over radio, targets a real aircraft, or touches a network I don't
> own. The included attack script refuses to run against any non-localhost host.

---

## Why this matters

MAVLink is the C2 and telemetry protocol used by the two dominant open-source
autopilots, ArduPilot and PX4. Its security posture is weak by design:

- **v1** has no authentication and no encryption — cleartext. Anyone who can put
  packets on the link can inject commands.
- **v2** adds *optional* message signing, but no encryption; adoption is limited
  and it has documented weaknesses (brute-forceable keys, replay windows).

So command injection, GPS spoofing, parameter tampering, and replay are realistic
threats against real aircraft. This project detects attacks carried *over the
drone's own control protocol* — the layer above raw RF detection.

---

## Architecture

```
   ┌── benign GCS (MAVProxy) ──┐
   │      (normal traffic)      │
 [ SITL drone ] ── UDP ─► capture ─► parse ─► detect ─► alerts
   │                       (live /   (pymav-    │        (console/JSON)
   └── attacker scripts ──►  replay)  link)     │
        (eval-only)                             ├─ L1  rule engine  (done)
                                                └─ L2  anomaly / ML (planned)
```

- **capture** — replay a saved capture for repeatable runs (`.tlog`), or tap a
  live UDP link.
- **parse** — `pymavlink` decodes bytes into normalized `Event` records (who sent
  it, what type, when, was it signed, and the payload).
- **detect** — two layers combined into a verdict.
- **alert** — explainable console output and JSON Lines for the eval harness.

## Detection: two layers on purpose

**Layer 1 — signature / rule engine** (implemented). Deterministic,
high-precision, explainable. Each rule returns a plain-language reason a human
operator can act on. Current rules: a command from an unexpected system id (rogue
GCS), and a disarm command — flagged **critical** when it carries the "force"
flag that bypasses the in-flight safety check.

**Layer 2 — anomaly / ML** (planned). Learn what normal flight looks like and
flag deviations the rules miss (unsupervised to start: Isolation Forest / One-Class
SVM / a small autoencoder over the feature set).

The tradeoff, stated plainly: **rules give precision and explainability; the ML
layer gives coverage of novel or subtle attacks.** Using both — and knowing why —
is the point.

---

## Quick start

**Requirements:** Python 3.12+ and [uv](https://docs.astral.sh/uv/). To generate
your own captures you also need ArduPilot SITL — see
[`lab/run_sitl.md`](lab/run_sitl.md) for the full lab setup (WSL2 + ArduPilot).

**Install and test:**

```bash
git clone https://github.com/<you>/mavlink-ids.git
cd mavlink-ids
uv sync                 # create the environment from the locked dependencies
uv run pytest -q        # run the test suite
```

**Get a capture.** Recorded flights (`.tlog`) live under `data/` and are
git-ignored (large, regenerable). Follow [`lab/run_sitl.md`](lab/run_sitl.md) to
fly a mission and save it to `data/benign/`.

**Run the detector over a capture:**

```python
from mavlink_ids.capture.replay import replay_file
from mavlink_ids.detect.rules import RuleEngine
from mavlink_ids.alert.sink import ConsoleSink

engine = RuleEngine()
sink = ConsoleSink()
for _ in engine.run(replay_file("data/benign/benign_flight_01.tlog"), sink):
    pass  # alerts print to the console as they fire
```

A single-command CLI (`uv run mavlink-ids <capture>`) is on the roadmap.

---

## Threat model

The attacks this system targets, all carried over the MAVLink C2 link:

| Attack | MAVLink mechanism | Impact | What gives it away |
|---|---|---|---|
| Command injection | `COMMAND_LONG` (arm/disarm, mode, RTL) | Vehicle hijack / crash | Command from an unexpected sysid; disarm mid-flight |
| GPS spoofing | Injected `GPS_INPUT` / falsified position | Flies to wrong place | Position jump beyond physical limits; velocity discontinuity |
| Parameter tampering | `PARAM_SET` on safety params | Disabled failsafes | Writes to critical params; unusual param traffic |
| Mission tampering | `MISSION_ITEM` rewrite | Altered flight path | Mid-flight mission changes from a new source |
| Replay | Re-sent valid packets | Repeated stale commands | Duplicate sequences/timestamps |
| GCS spoofing | Rogue system/component id | Unauthorized control | A second GCS appears; unexpected sysid/compid |
| DoS | `HEARTBEAT` flood, `RC_OVERRIDE` spam | Link saturation | Message-rate spikes; many sources |

## Results so far

The proving phase (full labeled dataset → measured recall / false-positive rate /
latency) is in progress. Established to date:

- **Command injection (forced disarm) is detected** — verified in unit tests; the
  rogue-sysid and forced-disarm rules both fire as `critical`.
- **Zero false positives** across all **99,930 events** of a real benign flight
  captured from ArduPilot SITL.
- The attack is real, not theoretical: injecting a forced disarm dropped the
  simulated drone from a hover to a **14.7 m/s** ground impact (vs. a normal
  0.5 m/s landing).

A baseline-vs-improved metrics table (rules only, then rules + anomaly layer) will
land here once the eval harness and dataset are complete.

## Roadmap

- [x] MAVLink parser → normalized events
- [x] Simulation lab (ArduPilot SITL) + benign capture
- [x] Eval-only attack script (command injection)
- [x] Layer 1 rule engine + explainable alerts
- [ ] Labeled dataset (more benign flights + all attack types)
- [ ] Eval harness: recall / precision / F1 / FPR / latency
- [ ] Layer 2 anomaly / ML detector
- [ ] CLI and a small alert-timeline dashboard

## Tech

Python 3.12 · [uv](https://docs.astral.sh/uv/) · [pymavlink](https://github.com/ArduPilot/pymavlink) · ArduPilot SITL · pytest

## Safety & scope

This is a **defensive** project. The attack scripts exist only to test the
detector against a **simulated** drone on localhost, and they refuse to run
against any non-localhost target. Nothing transmits over radio, targets a real
aircraft, or touches a network I don't own.
