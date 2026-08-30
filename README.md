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
