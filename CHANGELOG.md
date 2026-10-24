# Changelog — `otel-ebpf-span-aggregator`

All notable engineering changes to `otel-ebpf-span-aggregator` (`otel_aggregator`) are documented in this file.

## [0.3.0] — 2026-10-24
### Added
- Documented CLI diagnostic usage (`python -m otel_aggregator --self-test --json`) and deterministic invariant verification workflows in `README.md`.
- Added release history and semantic versioning audit trail in `CHANGELOG.md`.

## [0.2.1] — 2026-10-23
### Added
- Added automated CLI and runtime invariant regression suite in `tests/test_diagnostics_cli.py` covering seed determinism, negative-seed rejection, JSON output schema, and `--self-test` exit codes.

## [0.2.0] — 2026-10-21
### Added
- Added `src/otel_aggregator/diagnostics.py` (`run_diagnostic_suite`, `validate_runtime_invariants`) and module CLI runner `src/otel_aggregator/__main__.py`.
- Exported diagnostic helpers in `otel_aggregator.__all__`.

## [0.1.0] — 2026-10-19
### Added
- Initial architecture and core test suite: High-throughput OpenTelemetry tail-based trace sampler, DDSketch relative-error quantile aggregator, and Linux cgroup v2 CPU/OOM telemetry correlator.
