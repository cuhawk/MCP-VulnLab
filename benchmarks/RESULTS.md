# Wave 6 benchmark

Run `python benchmarks/run_bench.py --repeats 25` from the repository root
after installing the package. This run used Python 3.12.14 on x86-64 Linux.

| Corpus | Review fixtures | Hardened fixtures | True positives | False positives | False negatives | Precision | Recall | Hardened fixtures flagged | Median ms/file |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | 18 | 18 | 18 | 0 | 0 | 100% | 100% | 0 | 0.1173 |
| TypeScript | 14 | 14 | 14 | 0 | 0 | 100% | 100% | 0 | 0.0790 |
| Tool metadata | 5 | 5 | 6 | 0 | 0 | 100% | 100% | 0 | 0.0049 |
| All | 37 | 37 | 38 | 0 | 0 | 100% | 100% | 0 | 0.0799 |

Each fixture has a hand-labeled set of expected rule IDs or metadata reasons.
The benchmark counts each label once per fixture and counts a hardened
fixture as flagged if it emits any label. One metadata fixture expects both
an addition and a removal. The timings measure in-memory scanning after
one untimed scan per fixture, excluding file I/O and process startup.
The corpus consists of small synthetic examples paired with hardened
variants, so the accuracy results apply to this corpus.
