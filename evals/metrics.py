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
from dataclasses import dataclass

from mavlink_ids.parse.decoder import Event


def load_labeled(path: str) -> list[tuple[Event, str]]:
    """Read a labeled JSONL dataset back into (Event, label) pairs."""
    pairs: list[tuple[Event, str]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            label = row.pop("label")
            row.pop("attack_type", None)  # not needed for scoring
            pairs.append((Event(**row), label))
    return pairs


@dataclass
class EvalResult:
    """Confusion counts and the metrics derived from them."""

    tp: int  # attack events we flagged
    fp: int  # benign events we wrongly flagged
    fn: int  # attack events we missed
    tn: int  # benign events we correctly left alone
    latency_ms: float | None = None    # attack onset -> first alert, milliseconds
    latency_msgs: int | None = None    # attack onset -> first alert, message count

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


def evaluate(labeled: list[tuple[Event, str]], engine) -> EvalResult:
    """Run `engine` over labeled events and score it.

    `engine` is anything with a `.check(event) -> list` method (our RuleEngine).
    An event is "flagged" if the engine returns any alert for it. Latency is
    measured from the attack's first event to the first alert at or after it.
    """
    tp = fp = fn = tn = 0
    onset_index: int | None = None
    onset_time: float | None = None
    alert_index: int | None = None
    alert_time: float | None = None

    for i, (event, label) in enumerate(labeled):
        flagged = len(engine.check(event)) > 0
        is_attack = label == "attack"

        if is_attack and onset_index is None:
            onset_index, onset_time = i, event.timestamp

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

    return EvalResult(tp, fp, fn, tn, latency_ms, latency_msgs)
