"""Eval harness: run the detector over a labeled dataset and print the metrics.

Replays a labeled dataset through the rule engine and reports recall / precision
/ F1 / false-positive rate / latency — the "PROVE" numbers for the IDS.

Run from the project root:
    uv run python evals/run_suite.py
"""

from __future__ import annotations

import argparse

from mavlink_ids.detect.anomaly import AnomalyDetector
from mavlink_ids.detect.rules import RuleEngine

from metrics import EvalResult, load_labeled, score_from_flags


def format_report(dataset: str, result: EvalResult) -> str:
    """Render an EvalResult as a readable text block."""
    lat_ms = "n/a" if result.latency_ms is None else f"{result.latency_ms:.1f} ms"
    lat_msg = "n/a" if result.latency_msgs is None else f"{result.latency_msgs} msgs"
    total = result.tp + result.fp + result.fn + result.tn
    lines = [
        f"Dataset: {dataset}",
        "=" * 50,
        f"  events            : {total}",
        f"  true positives    : {result.tp}",
        f"  false negatives   : {result.fn}",
        f"  false positives   : {result.fp}",
        f"  true negatives    : {result.tn}",
        "-" * 50,
        f"  recall            : {result.recall:.3f}",
        f"  precision         : {result.precision:.3f}",
        f"  F1                : {result.f1:.3f}",
        f"  false-positive rate: {result.false_positive_rate:.5f}",
        f"  detection latency : {lat_msg} / {lat_ms}",
    ]
    if result.per_type:
        lines.append("-" * 50)
        lines.append("  per-attack-type recall:")
        for atype, (caught, total_t) in sorted(result.per_type.items()):
            rate = caught / total_t if total_t else 0.0
            lines.append(f"    {atype:18}: {caught}/{total_t}  ({rate:.0%})")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate the rule detector on a labeled dataset."
    )
    parser.add_argument(
        "--dataset",
        default="data/labeled/attack_disarm_01.jsonl",
        help="path to a labeled JSONL dataset",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.00001,
        help="anomaly threshold: expected fraction of outliers (lower = stricter)",
    )
    args = parser.parse_args()

    labeled = load_labeled(args.dataset)
    events = [event for event, _, _ in labeled]

    # Layer 1 (rules) — fast per-event.
    rules = RuleEngine()
    rule_flags = [bool(rules.check(event)) for event in events]
    baseline = score_from_flags(labeled, rule_flags)
    print(format_report("rules only (Layer 1)", baseline))
    print()

    # Layer 2 (anomaly) — train on benign, then batch-score the whole stream.
    benign_events = [event for event, label, _ in labeled if label == "benign"]
    anomaly = AnomalyDetector(contamination=args.contamination).fit(benign_events)
    anomaly_flags = anomaly.predict_outliers(events)

    # Combined verdict: an event is flagged if EITHER layer flags it.
    combined_flags = [r or a for r, a in zip(rule_flags, anomaly_flags)]
    improved = score_from_flags(labeled, combined_flags)
    print(format_report("rules + anomaly (Layer 1 + Layer 2)", improved))


if __name__ == "__main__":
    main()
