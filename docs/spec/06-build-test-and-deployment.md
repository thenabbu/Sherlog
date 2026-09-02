# 06 — Build, test, validation, and deployment specification

## 1. Packaging contract

`pyproject.toml` uses `setuptools.build_meta`, project name `sat-sa`, version `0.1.0`, Python `>=3.10`, and console script:

```toml
[project.scripts]
satsa = "sat_sa.cli:app"
```

Runtime dependencies are pandas, NumPy, Pydantic, Typer, Rich, PyArrow, and PyYAML at the minimum versions defined in `pyproject.toml`. Development adds pytest.

## 2. Air-gapped installation

On an approved connected build machine, create a vetted wheelhouse for the exact Python/platform target. Transfer source and wheelhouse to the controlled environment. Install with no package index:

```powershell
python -m pip install --no-index --find-links=./wheelhouse -r requirements.txt
python -m pip install --no-index --find-links=./wheelhouse -e . --no-build-isolation
```

`--no-build-isolation` prevents pip from attempting to download build requirements in a sealed environment. The wheelhouse MUST include a compatible setuptools wheel and all package transitive dependencies.

## 3. Security and offline release gates

Before release, MUST verify:

```powershell
python -m pytest -q
```

```powershell
rg -n "requests|urllib|socket" sat_sa
```

The network-import check should produce no results. It is a basic guard, not a complete network-security review; a production deployment SHOULD use static analysis, package vulnerability scanning against an offline mirror, signed artifact manifests, and host network controls.

## 4. Required regression behaviour

The test suite must cover at least:

1. synthetic injection detection for all three signal types;
2. malformed input becoming a reject rather than disappearing;
3. ranking output presence and one-based rank;
4. streaming generator record count/parquet row count;
5. explicit runtime limits being honoured;
6. adaptive controller respecting small explicit batch floors;
7. adaptive controller scale-up with headroom and scale-down under critical memory pressure.

The reference suite is `tests/test_core.py`. A replica SHOULD additionally add integration tests that run a small full CLI pipeline in both adaptive and fixed modes.

## 5. Synthetic validation procedure

Run this sequence after each detector/runtime change:

```powershell
satsa generate-synth --entities 8 --alerts-per-entity 50 --seed 7 --anomaly-rate 0.25 --batch-size 25 --no-adaptive --out validation_run\synth
```

```powershell
satsa ingest --input validation_run\synth --format csv --batch-size 25 --workers 1 --no-adaptive --out validation_run\normalized
```

```powershell
satsa detect --data validation_run\normalized --detectors execution_gaps,negative_space --config detector_config.yaml --batch-size 25 --workers 1 --no-adaptive --out validation_run\results\flags.json
```

```powershell
satsa validate --flags validation_run\results\flags.json --synth-ground-truth validation_run\synth\ground_truth.parquet
```

For this controlled data/seed, the expected result is two injected/detected cases for each detector and precision, recall, F1 of 1.000. It validates the implementation's ability to recover injected conditions; it does not establish real-world supervisory effectiveness.

## 6. Real-world validation protocol

Before operational adoption:

1. Collect anonymised periodic submissions and independent examiner findings.
2. Freeze a documented configuration file and dataset version.
3. Run SAT-SA blind to examiner outcomes.
4. Compare flagged entities/alerts/assets with the manual review sample; report precision, recall, false-positive review burden, and missed material findings.
5. Review threshold changes with supervisory subject-matter experts.
6. Retain inputs, configuration hash, code version, output report, and reviewer disposition for audit.
7. Revalidate after changes to detectors, schema, peer grouping, data source mappings, or runtime/storage implementation.

## 7. Operational capacity guidance

Capacity is governed by source file size, disk throughput, available RAM, active antivirus, and concurrent use. Parquet intermediate storage and temp duration files require free disk space in addition to source CSV/parquet. The tool's 2M-alert example has been exercised through generation, CSV ingest, and two-pass detection. Production sizing SHOULD be benchmarked on the intended controlled hardware with a copy of representative, non-sensitive data.
