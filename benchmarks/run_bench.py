"""Run the offline labeled corpus and report accuracy and per-file latency."""

import argparse
import json
import platform
from statistics import median
from time import perf_counter_ns

from corpus import fixtures


def evaluate(corpus, repeats):
    true_positive = false_positive = false_negative = clean_false_positive = 0
    elapsed = []
    mismatches = []
    for fixture in corpus:
        actual = fixture.scan()
        true_positive += len(actual & fixture.expected)
        false_positive += len(actual - fixture.expected)
        false_negative += len(fixture.expected - actual)
        clean_false_positive += int(not fixture.expected and bool(actual))
        if actual != fixture.expected:
            mismatches.append({
                "fixture": fixture.name,
                "expected": sorted(fixture.expected),
                "actual": sorted(actual),
            })
        for _ in range(repeats):
            start = perf_counter_ns()
            fixture.scan()
            elapsed.append((perf_counter_ns() - start) / 1_000_000)
    clean = sum(not fixture.expected for fixture in corpus)
    return {
        "fixtures": len(corpus),
        "review_fixtures": len(corpus) - clean,
        "clean_fixtures": clean,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": true_positive / (true_positive + false_positive) if true_positive + false_positive else None,
        "recall": true_positive / (true_positive + false_negative) if true_positive + false_negative else None,
        "clean_false_positive_files": clean_false_positive,
        "median_ms_per_file": round(median(elapsed), 4),
        "mismatches": mismatches,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=25)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    corpus = list(fixtures())
    groups = {"all": corpus}
    groups.update({kind: [fixture for fixture in corpus if fixture.kind == kind]
                   for kind in ("py", "ts", "metadata")})
    print(json.dumps({
        "python": platform.python_version(),
        "platform": platform.platform(),
        "repeats": args.repeats,
        "results": {name: evaluate(group, args.repeats) for name, group in groups.items()},
    }, indent=2))


if __name__ == "__main__":
    main()
