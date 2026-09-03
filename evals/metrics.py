"""Scoring for the detector: load labeled data and compute detection metrics.

Given a labeled dataset (each event tagged benign/attack) and the rule engine's
verdict on each event, we count the four outcomes and derive the numbers that
tell us whether the IDS is any good:

  * recall     — of the real attacks, how many did we catch?
  * precision  — of our alerts, how many were real attacks?
  * FPR        — of benign events, how many did we wrongly alarm on?
  * F1         — the balance of precision and recall.

A high recall with a high false-positive rate is a useless IDS, so FPR matters
as much as recall.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from mavlink_ids.parse.decoder import Event


def load_labeled(path: str) -> list[tuple[Event, str, str]]:
    """Read a labeled JSONL dataset into (Event, label, attack_type) triples.

    `attack_type` is "" for benign events; for attacks it names the kind, so we
    can report a per-attack-type detection rate.
    """
    rows: list[tuple[Event, str, str]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            label = row.pop("label")
            attack_type = row.pop("attack_type", "")
            rows.append((Event(**row), label, attack_type))
    return rows


@dataclass
class EvalResult:
    """Confusion counts and the metrics derived from them."""

    tp: int  # attack events we flagged
    fp: int  # benign events we wrongly flagged
    fn: int  # attack events we missed
    tn: int  # benign events we correctly left alone
    latency_ms: float | None = None    # attack onset -> first alert, milliseconds
    latency_msgs: int | None = None    # attack onset -> first alert, message count
    # attack_type -> (caught, total), for per-attack detection rate
    per_type: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        caught = self.tp + self.fn
        return self.tp / caught if caught else 0.0

    @property
    def precision(self) -> float:
        alerted = self.tp + self.fp
        return self.tp / alerted if alerted else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        benign = self.fp + self.tn
        return self.fp / benign if benign else 0.0


def score_from_flags(
    labeled: list[tuple[Event, str, str]], flags: list[bool]
) -> EvalResult:
    """Score precomputed per-event verdicts against the labels.

    `flags[i]` is True if the detector flagged event i. Keeping the counting
    separate from the detector lets us score fast batched predictions, not just
    per-event `.check()` calls.
    """
    tp = fp = fn = tn = 0
    onset_index: int | None = None
    onset_time: float | None = None
    alert_index: int | None = None
    alert_time: float | None = None
    # attack_type -> [caught, total]
    type_counts: dict[str, list[int]] = {}

    for i, ((event, label, attack_type), flagged) in enumerate(zip(labeled, flags)):
        is_attack = label == "attack"

        if is_attack:
            if onset_index is None:
                onset_index, onset_time = i, event.timestamp
            counts = type_counts.setdefault(attack_type, [0, 0])
            counts[1] += 1              # total of this type
            if flagged:
                counts[0] += 1          # caught

        # First alert at or after the attack onset (measures detection latency).
        if onset_index is not None and flagged and alert_index is None:
            alert_index, alert_time = i, event.timestamp

        if is_attack and flagged:
            tp += 1
        elif is_attack and not flagged:
            fn += 1
        elif not is_attack and flagged:
            fp += 1
        else:
            tn += 1

    latency_ms: float | None = None
    latency_msgs: int | None = None
    if onset_index is not None and alert_index is not None:
        latency_msgs = alert_index - onset_index
        latency_ms = (alert_time - onset_time) * 1000.0  # type: ignore[operator]

    per_type = {atype: (c[0], c[1]) for atype, c in type_counts.items()}
    return EvalResult(tp, fp, fn, tn, latency_ms, latency_msgs, per_type)


def evaluate(labeled: list[tuple[Event, str, str]], engine) -> EvalResult:
    """Run a detector over labeled events and score it (per-event `.check()`).

    `engine` is anything with `.check(event) -> list`. Fine for the fast rule
    engine; for the anomaly model, prefer batched flags via `score_from_flags`.
    """
    flags = [len(engine.check(event)) > 0 for event, _, _ in labeled]
    return score_from_flags(labeled, flags)
