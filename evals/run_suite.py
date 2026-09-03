"""Eval harness: run the detector over a labeled dataset and print the metrics.

Replays a labeled dataset through the rule engine and reports recall / precision
/ F1 / false-positive rate / latency — the "PROVE" numbers for the IDS.

Run from the project root:
    uv run python evals/run_suite.py
"""

from __future__ import annotations

import argparse

from mavlink_ids.detect.rules import RuleEngine

from metrics import EvalResult, evaluate, load_labeled


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
    args = parser.parse_args()

    labeled = load_labeled(args.dataset)
    result = evaluate(labeled, RuleEngine())
    print(format_report(args.dataset, result))


if __name__ == "__main__":
    main()
