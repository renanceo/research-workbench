# Research Workbench — Public Research Preview

> **Research preview — not a validated paper-positioning service. Real-manuscript diagnostics and paid use remain unavailable until Gate 1 is completed.**

This directory contains the first executable Gate 0 evidence for the open
Workbench. It intentionally contains no private protocol, venue data, prompts,
benchmark answers, or user manuscripts.

See [PUBLIC_RESEARCH_PREVIEW.md](PUBLIC_RESEARCH_PREVIEW.md) for the exact
public status, limits, and offline synthetic demo.

Included in v1:

- JSON Schema 2020-12 contracts for task, result, failure, cancellation,
  timeout, task event, and settlement event payloads;
- synthetic positive and negative fixtures;
- a server-controlled diagnostic state machine;
- an idempotent one-authorization/one-capture settlement ledger;
- contract, transition, replay, over-capture, and safe-failure tests.

Run the evidence suite:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install 'jsonschema>=4.23,<5' 'pypdf>=5,<7'
.venv/bin/python -m unittest discover -s tests -v
```

Run the entirely synthetic, offline product-shape preview:

```bash
.venv/bin/python scripts/run_public_preview.py
```

The parser isolation tests require macOS `sandbox-exec` and must run outside an
already nested application sandbox. A Linux CI run must replace this policy
with an isolated runner or container that also enforces a hard memory limit.

The contracts are frozen as `contract_version: 1.0`. A breaking change requires
a new contract version; it must not overwrite v1 or prior run evidence.

## Research participation

Gate 1 currently needs one independent manual paper-positioning operator. See
[MANUAL_OPERATOR_INTEREST.md](MANUAL_OPERATOR_INTEREST.md) for the public
eligibility and conflict rules. The private protocol, evaluation cases,
prompts, profiles, thresholds, calibration records, and judge materials are not
part of this repository or the public qualification intake.

## License

The public Workbench software and documentation are licensed under the
[Apache License 2.0](LICENSE). Private protocols, prompts, profiles, benchmark
materials, calibration assets, and user manuscripts are not included and are
not licensed by this repository.
