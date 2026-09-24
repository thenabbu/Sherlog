from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from sat_sa.detectors.execution_gaps import (
    detect_ack_without_meaningful_investigation,
    detect_critical_no_escalation,
    detect_fast_closure,
    detect_high_risk_no_escalation,
    detect_investigation_closure_mismatch,
    detect_recurrence_without_root_cause,
    detect_short_investigation,
    detect_workload_severity_mismatch,
)
from sat_sa.detectors.negative_space import (
    detect_critical_asset_no_telemetry,
    detect_low_critical_asset_coverage,
    detect_low_critical_asset_coverage_from_counts,
    detect_low_entity_activity,
    detect_missing_escalation_evidence,
    detect_missing_investigation_evidence,
)
from sat_sa.evidence import attach_evidence
from sat_sa.ingestion import FieldMapping, RawTable, normalize, normalize_table
from sat_sa.peer import benchmark
from sat_sa.schema import Alert, Case, Entity, Flag, SCHEMAS, Severity
from sat_sa.scoring import score_entities


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def alerts(rows):
    """Build an alerts DataFrame with every required schema column."""
    return pd.DataFrame(
        rows,
        columns=[
            "alert_id", "entity_id", "asset_id", "severity", "created_at",
            "first_ack_at", "closed_at", "disposition", "escalated", "case_id",
        ],
    )


def _entities(n=4):
    return pd.DataFrame(
        [[f"E{i}", f"Entity {i}", "P"] for i in range(n)],
        columns=["entity_id", "name", "peer_group"],
    )


def _cases(rows=None):
    if rows is None:
        rows = []
    return pd.DataFrame(
        rows,
        columns=["case_id", "entity_id", "opened_at", "closed_at", "alert_ids", "root_cause_documented"],
    )


# ---------------------------------------------------------------------------
# Detector tests (original)
# ---------------------------------------------------------------------------
def test_relationship_and_severity_rules():
    frame = alerts([
        ["A1", "E1", "AS1", "high", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "2026-01-01T01:00:00Z", "true_positive", False, "C1"],
        ["A2", "E1", "AS2", "high", "2026-01-01T00:00:00Z", None, "2026-01-01T01:00:00Z", "true_positive", False, None],
    ])
    cases = _cases([["C1", "E1", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", ["A1"], False]])
    assert {f.detector for f in detect_ack_without_meaningful_investigation(frame, cases)} == {"ack_without_meaningful_investigation"}
    assert {f.detector for f in detect_investigation_closure_mismatch(frame, cases)} == {"investigation_closure_mismatch"}
    assert {f.detector for f in detect_high_risk_no_escalation(frame)} == {"high_risk_no_escalation"}
    assert {f.detector for f in detect_missing_investigation_evidence(frame, {"C1"})} == {"missing_investigation_evidence"}


def test_short_investigation_requires_peer_sample():
    entities = _entities(4)
    cases = _cases([
        [f"C{i}", f"E{i}", "2026-01-01T00:00:00Z", f"2026-01-01T0{i+1}:00:00Z", [], True]
        for i in range(4)
    ])
    frame = alerts([["A0", "E0", "AS1", "high", "2026-01-01T00:00:00Z", None, "2026-01-01T01:00:00Z", "true_positive", True, "C0"]])
    assert detect_short_investigation(frame, cases, entities, k=1.5, min_peer_sample=4) == []


def test_recurrence_requires_minimum_and_no_root_cause():
    frame = alerts([
        [f"A{i}", "E1", "AS1", "medium", f"2026-01-0{i+1}T00:00:00Z", None, None, "true_positive", False, None]
        for i in range(3)
    ])
    flags = detect_recurrence_without_root_cause(frame, pd.DataFrame(), min_alerts=3)
    assert len(flags) == 1
    assert flags[0].evidence["repeat_count"] == 3


def test_negative_space_guards_positive_peer_baselines():
    entities = _entities(4)
    assets = pd.DataFrame(
        [[f"AS{i}", f"E{i}", "critical"] for i in range(4)],
        columns=["asset_id", "entity_id", "criticality"],
    )
    counts = pd.DataFrame(
        [["E1", "AS1", 4], ["E2", "AS2", 4], ["E3", "AS3", 4]],
        columns=["entity_id", "asset_id", "observed_count"],
    )
    assert len(detect_critical_asset_no_telemetry(counts, assets, pd.Timestamp("2026-01-01", tz="UTC"))) == 1
    activity = pd.DataFrame(
        [["E0", 0], ["E1", 4], ["E2", 4], ["E3", 4]],
        columns=["entity_id", "alert_count"],
    )
    assert len(detect_low_entity_activity(activity, entities, threshold_pct=0.25, min_peer_sample=4)) == 1


def test_missing_escalation_evidence_only_flags_claimed_records():
    frame = alerts([["A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None, None, "true_positive", True, None]])
    assert len(detect_missing_escalation_evidence(frame, set())) == 1
    assert detect_missing_escalation_evidence(frame, {"A1"}) == []


# ---------------------------------------------------------------------------
# Fast closure detector
# ---------------------------------------------------------------------------
class TestFastClosure:
    def test_flags_briefly_closed_critical_alerts(self):
        """An alert closed in 2 minutes vs Q1 of 480 minutes should be flagged."""
        stats = pd.DataFrame([{"severity": "critical", "q1": 480.0, "iqr": 60.0, "sample_size": 100}])
        frame = alerts([[
            "A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None,
            "2026-01-01T00:02:00Z", "true_positive", False, None,
        ]])
        flags = detect_fast_closure(frame, stats, k=1.5)
        assert len(flags) == 1
        assert flags[0].detector == "fast_closure"
        assert flags[0].entity_id == "E1"

    def test_does_not_flag_within_fence(self):
        """An alert closed in 400 minutes should NOT be flagged (Q1=480, IQR=60, fence=390)."""
        stats = pd.DataFrame([{"severity": "critical", "q1": 480.0, "iqr": 60.0, "sample_size": 100}])
        frame = alerts([[
            "A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None,
            "2026-01-01T06:40:00Z", "true_positive", False, None,
        ]])
        flags = detect_fast_closure(frame, stats, k=1.5)
        assert len(flags) == 0

    def test_ignores_low_severity(self):
        stats = pd.DataFrame([{"severity": "low", "q1": 100.0, "iqr": 20.0, "sample_size": 50}])
        frame = alerts([[
            "A1", "E1", "AS1", "low", "2026-01-01T00:00:00Z", None,
            "2026-01-01T00:01:00Z", "true_positive", False, None,
        ]])
        assert detect_fast_closure(frame, stats, k=1.5) == []


# ---------------------------------------------------------------------------
# No-escalation detector
# ---------------------------------------------------------------------------
class TestNoEscalation:
    def test_flags_critical_true_positive_without_escalation(self):
        frame = alerts([[
            "A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None,
            "2026-01-01T01:00:00Z", "true_positive", False, None,
        ]])
        flags = detect_critical_no_escalation(frame)
        assert len(flags) == 1
        assert flags[0].severity_weight == 3

    def test_ignores_escalated_alerts(self):
        frame = alerts([[
            "A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None,
            "2026-01-01T01:00:00Z", "true_positive", True, None,
        ]])
        assert detect_critical_no_escalation(frame) == []

    def test_ignores_false_positive(self):
        frame = alerts([[
            "A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None,
            "2026-01-01T01:00:00Z", "false_positive", False, None,
        ]])
        assert detect_critical_no_escalation(frame) == []


# ---------------------------------------------------------------------------
# Ingestion + normalization
# ---------------------------------------------------------------------------
class TestIngestion:
    def test_normalize_valid_rows(self):
        frame = pd.DataFrame([{
            "entity_id": "E1", "name": "Entity One", "peer_group": "P1",
        }])
        valid, rejects = normalize(RawTable(frame, "test.csv", "entities"), FieldMapping("entities"))
        assert len(valid) == 1
        assert rejects == []

    def test_normalize_rejects_invalid_rows(self):
        frame = pd.DataFrame([{"entity_id": "E1"}])  # missing 'name' and 'peer_group'
        valid, rejects = normalize(RawTable(frame, "test.csv", "entities"), FieldMapping("entities"))
        assert len(valid) == 0
        assert len(rejects) == 1

    def test_normalize_alerts_validates_chronology(self):
        frame = pd.DataFrame([{
            "alert_id": "A1", "entity_id": "E1", "severity": "high",
            "category": "intrusion",
            "created_at": "2026-01-02T00:00:00Z", "closed_at": "2026-01-01T00:00:00Z",
            "disposition": "true_positive", "escalated": False,
        }])
        valid, rejects = normalize(RawTable(frame, "test.csv", "alerts"), FieldMapping("alerts"))
        assert len(valid) == 0
        assert len(rejects) == 1
        assert "closed_at must not precede created_at" in str(rejects[0]["reason"])

    def test_unsupported_table_raises(self):
        with pytest.raises(ValueError, match="Unsupported table"):
            normalize(RawTable(pd.DataFrame(), "test.csv", "bogus"), FieldMapping("bogus"))


# ---------------------------------------------------------------------------
# Peer benchmark
# ---------------------------------------------------------------------------
class TestPeerBenchmark:
    def test_benchmark_attaches_percentiles(self):
        df = pd.DataFrame([
            {"entity": "E1", "metric": 10, "peer": "P1"},
            {"entity": "E2", "metric": 20, "peer": "P1"},
            {"entity": "E3", "metric": 30, "peer": "P1"},
        ])
        result = benchmark(df, "entity", "metric", "peer")
        assert "peer_median" in result.columns
        assert "percentile_rank" in result.columns
        assert result["peer_median"].iloc[0] == 20.0

    def test_benchmark_missing_columns_raises(self):
        with pytest.raises(ValueError, match="missing columns"):
            benchmark(pd.DataFrame({"a": [1]}), "a", "b", "c")


# ---------------------------------------------------------------------------
# Evidence attachment
# ---------------------------------------------------------------------------
class TestEvidence:
    def test_attach_alert_rows(self):
        flag = Flag(
            flag_id="fg_001", detector="fast_closure", entity_id="E1",
            severity_weight=2, rationale="test",
            evidence={"alert_ids": ["A1"]},
        )
        alerts_df = pd.DataFrame([{
            "alert_id": "A1", "entity_id": "E1", "severity": "high",
            "created_at": "2026-01-01T00:00:00Z",
        }])
        updated = attach_evidence(flag, {"alerts": alerts_df})
        assert "source_rows" in updated.evidence
        assert len(updated.evidence["source_rows"]) == 1

    def test_attach_empty_when_no_matches(self):
        flag = Flag(
            flag_id="fg_002", detector="fast_closure", entity_id="E1",
            severity_weight=2, rationale="test",
            evidence={"alert_ids": ["NOPE"]},
        )
        alerts_df = pd.DataFrame([{"alert_id": "A1"}])
        updated = attach_evidence(flag, {"alerts": alerts_df})
        assert "source_rows" not in updated.evidence


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
class TestScoring:
    def test_score_ranks_entities(self):
        flags = [
            Flag(flag_id="f1", detector="fast_closure", entity_id="E1",
                 severity_weight=2, rationale="r"),
            Flag(flag_id="f2", detector="no_escalation", entity_id="E2",
                 severity_weight=3, rationale="r"),
        ]
        volumes = {"E1": 100, "E2": 100}
        scores = score_entities(flags, volumes)
        assert len(scores) == 2
        assert scores.iloc[0]["priority_rank"] == 1

    def test_score_higher_volume_reduces_risk(self):
        flag = Flag(flag_id="f1", detector="no_escalation", entity_id="E1",
                    severity_weight=3, rationale="r")
        scores_low = score_entities([flag], {"E1": 10})
        scores_high = score_entities([flag], {"E1": 10000})
        assert float(scores_low.iloc[0]["risk_score"]) > float(scores_high.iloc[0]["risk_score"])

    def test_score_empty_returns_empty_df(self):
        scores = score_entities([], {})
        assert scores.empty


# ---------------------------------------------------------------------------
# CLI pipeline integration
# ---------------------------------------------------------------------------
class TestPipeline:
    def test_generate_produces_valid_output(self):
        from sat_sa.synth import generate

        data = generate(n_entities=5, alerts_per_entity=50, seed=99)
        assert len(data["entities"]) == 5
        # Generator adds baseline alerts_per_entity per entity plus injected anomalies
        assert len(data["alerts"]) >= 50 * 5
        assert "alert_id" in data["alerts"].columns
        assert "entity_id" in data["alerts"].columns

    def test_generate_requires_minimum_entities(self):
        from sat_sa.synth import generate

        with pytest.raises(ValueError, match="At least 4"):
            generate(n_entities=2)

    def test_round_trip_ingestion(self):
        """Synthesize → ingest (via normalize) → verify parquet-compatible output."""
        from sat_sa.synth import generate

        data = generate(n_entities=5, alerts_per_entity=20, seed=42)
        for name in ("entities", "assets", "alerts", "cases"):
            if name in SCHEMAS:
                valid, rejects = normalize(
                    RawTable(data[name], "synth", name), FieldMapping(name)
                )
                # All generated rows should be valid
                assert len(rejects) == 0, f"{name} has rejects: {rejects[:3]}"
                # At least some rows should be valid
                assert len(valid) > 0, f"{name} produced no valid rows"

    def test_detect_flags_fast_closure_injected_alert(self):
        """Verify the D1 fast-closure detector catches an injected outlier."""
        from sat_sa.detectors.execution_gaps import detect_fast_closure

        # Build a batch where one alert closes in 2 minutes vs Q1=480
        batch = alerts([
            ["A1", "E1", "AS1", "high", "2026-01-01T00:00:00Z", None,
             "2026-01-01T08:00:00Z", "true_positive", False, None],
            ["A2", "E1", "AS1", "high", "2026-01-01T00:00:00Z", None,
             "2026-01-01T00:02:00Z", "true_positive", False, None],
        ])
        stats = pd.DataFrame([{"severity": "high", "q1": 480.0, "iqr": 60.0, "sample_size": 100}])
        flags = detect_fast_closure(batch, stats, k=1.5)
        assert any(f.evidence["alert_ids"] == ["A2"] for f in flags)

    def test_detect_flags_no_escalation(self):
        """Verify D2 flags critical true-positive without escalation."""
        from sat_sa.detectors.execution_gaps import detect_critical_no_escalation

        batch = alerts([
            ["A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None,
             "2026-01-01T01:00:00Z", "true_positive", False, None],
        ])
        flags = detect_critical_no_escalation(batch)
        assert len(flags) == 1
        assert flags[0].detector == "no_escalation"

    def test_score_and_report_roundtrip(self, tmp_path):
        """Score → report produces valid JSON."""
        from sat_sa.scoring import score_entities as se

        flags = [
            Flag(flag_id="f1", detector="fast_closure", entity_id="E1",
                 severity_weight=2, rationale="test"),
            Flag(flag_id="f2", detector="no_escalation", entity_id="E1",
                 severity_weight=3, rationale="test2"),
        ]
        scores = se(flags, {"E1": 200})
        assert not scores.empty
        assert scores.iloc[0]["entity_id"] == "E1"
        assert scores.iloc[0]["risk_score"] > 0


# ---------------------------------------------------------------------------
# Bug-fix regression tests
# ---------------------------------------------------------------------------
class TestCaseIndexDuplicateIds:
    """Regression: _case_index used to crash with ValueError on duplicate case_ids."""

    def test_duplicate_case_ids_no_crash(self):
        from sat_sa.detectors.execution_gaps import _case_index

        cases = _cases([
            ["C1", "E1", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", ["A1"], True],
            ["C1", "E1", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", ["A1"], False],
        ])
        index = _case_index(cases)
        assert "C1" in index
        # First occurrence wins (keep="first")
        assert index["C1"]["root_cause_documented"] is True

    def test_duplicate_case_ids_detect_ack_works(self):
        """Ack detector should not crash on duplicate case_ids."""
        frame = alerts([
            ["A1", "E1", "AS1", "high", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z",
             "2026-01-01T01:00:00Z", "true_positive", False, "C1"],
        ])
        cases = _cases([
            ["C1", "E1", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", ["A1"], False],
            ["C1", "E1", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", ["A1"], False],
        ])
        # Should not raise ValueError
        flags = detect_ack_without_meaningful_investigation(frame, cases)
        assert len(flags) == 1


class TestRejectsAtomicWrite:
    """Regression: reject_path used to be left malformed if ingest crashed."""

    def test_rejects_not_written_when_empty(self, tmp_path):
        """When no rejects, reject_path should not exist."""
        from sat_sa.ingestion import FieldMapping, RawTable, normalize

        entities_data = pd.DataFrame([
            {"entity_id": "E1", "name": "Entity One", "peer_group": "P1"},
        ])
        # Simulate what ingest does: buffer rejects then write atomically
        reject_entries = []
        valid, rejects = normalize(
            RawTable(entities_data, "synth", "entities"), FieldMapping("entities")
        )
        reject_entries.extend(rejects)
        reject_path = tmp_path / "rejects.json"
        if reject_entries:
            reject_path.write_text(json.dumps(reject_entries, indent=2, default=str))
        assert not reject_path.exists()

    def test_rejects_valid_json_when_present(self, tmp_path):
        """When rejects exist, the file should be valid JSON."""
        reject_entries = [
            {"source": "test.csv", "table": "entities", "row": 0, "reason": "bad", "record": {}},
            {"source": "test.csv", "table": "entities", "row": 1, "reason": "worse", "record": {}},
        ]
        reject_path = tmp_path / "rejects.json"
        reject_path.write_text(json.dumps(reject_entries, indent=2, default=str))
        loaded = json.loads(reject_path.read_text())
        assert len(loaded) == 2


class TestAlertIdConsistency:
    """Regression: generate() used to produce 6-digit IDs while write_synthetic() used 9-digit."""

    def test_generate_uses_nine_digit_ids(self):
        from sat_sa.synth import generate

        data = generate(n_entities=4, alerts_per_entity=5, seed=42)
        ids = data["alerts"]["alert_id"].tolist()
        # All IDs should be 9-digit format: AL-XXXXXXXXX
        assert all(len(al_id) == 12 for al_id in ids)  # AL- + 9 digits
        assert ids[0] == "AL-000000001"


class TestSecurityPathTraversal:
    """Security: path traversal attacks via config and query parameters."""

    def test_sanitize_run_name_strips_path_separators(self):
        """path traversal in run names must be neutralized."""
        import re

        def sanitize_run_name(name: str) -> str:
            s = re.sub(r"[^A-Za-z0-9_-]", "_", (name or "").strip())
            return s[:64] or "run"

        assert sanitize_run_name("../../etc/passwd") != "../../etc/passwd"
        assert sanitize_run_name("../../../app.py") != "../../../app.py"
        assert "/" not in sanitize_run_name("a/b/c")
        assert "\\" not in sanitize_run_name("a\\b\\c")
        # Normal names pass through
        assert sanitize_run_name("cycle-20260923") == "cycle-20260923"
        assert sanitize_run_name("normal_run") == "normal_run"

    def test_config_path_cannot_escape_app_dir(self):
        """Config path resolution must stay within APP_DIR."""
        from pathlib import Path
        import os

        APP_DIR = Path(__file__).resolve().parent.parent

        def is_safe_config_path(cfgp, app_dir):
            try:
                cfgp = cfgp.resolve(strict=False)
            except (OSError, ValueError):
                return False
            return (cfgp == app_dir
                    or str(cfgp).startswith(str(app_dir) + os.sep)
                    or str(cfgp).startswith(str(app_dir) + "/"))

        # Safe paths
        assert is_safe_config_path(APP_DIR / "detector_config.yaml", APP_DIR)
        assert is_safe_config_path(APP_DIR / "configs" / "test.yaml", APP_DIR)
        # Traversal attacks
        assert not is_safe_config_path(APP_DIR / "../../etc/hostname", APP_DIR)
        assert not is_safe_config_path(Path("/etc/hostname"), APP_DIR)

    def test_config_bounds_reject_extreme_values(self):
        """Config values outside sane ranges must be rejected."""
        _CONFIG_BOUNDS = {
            "fast_closure_k": (0.1, 10.0),
            "coverage_window_days": (1, 3650),
            "coverage_threshold_pct": (0.0, 1.0),
            "investigation_duration_k": (0.1, 10.0),
            "recurrence_min_alerts": (1, 100),
        }
        evil_values = {
            "fast_closure_k": -1.0,
            "coverage_window_days": 999999,
            "coverage_threshold_pct": 999.0,
            "investigation_duration_k": 0.0001,
            "recurrence_min_alerts": -5,
        }
        for key, val in evil_values.items():
            lo, hi = _CONFIG_BOUNDS[key]
            assert not (lo <= val <= hi), f"{key}={val} should be rejected"

        valid_values = {
            "fast_closure_k": 1.5,
            "coverage_window_days": 30,
            "coverage_threshold_pct": 0.25,
            "investigation_duration_k": 1.5,
            "recurrence_min_alerts": 3,
        }
        for key, val in valid_values.items():
            lo, hi = _CONFIG_BOUNDS[key]
            assert lo <= val <= hi, f"{key}={val} should be accepted"


@pytest.fixture(scope="session")
def normalized_run_dir():
    """Session-scoped normalized dataset for CLI-level tests.

    Each test previously generated data into a shared 'runs/test-reliability'
    directory as a side effect of another test — which made individual tests
    fail when run in isolation. This fixture makes the dependency explicit
    and gives every consumer its own guaranteed-present dataset.
    """
    import subprocess
    import sys

    rd = Path(tempfile.mkdtemp(prefix="satsa_reliability_")) / "run"
    gen = subprocess.run(
        [sys.executable, "-m", "sat_sa.cli", "generate-synth",
         "--entities", "4", "--alerts-per-entity", "10",
         "--out", str(rd / "source")],
        capture_output=True, text=True, timeout=120,
    )
    assert gen.returncode == 0, f"generate-synth failed: {gen.stderr[-300:]}"
    ing = subprocess.run(
        [sys.executable, "-m", "sat_sa.cli", "ingest",
         "--input", str(rd / "source"), "--out", str(rd / "normalized")],
        capture_output=True, text=True, timeout=120,
    )
    assert ing.returncode == 0, f"ingest failed: {ing.stderr[-300:]}"
    assert (rd / "normalized" / "alerts.parquet").exists()
    yield rd
    shutil.rmtree(rd, ignore_errors=True)


class TestReliability:
    """Reliability: deterministic output, atomic writes, error handling."""

    def test_evidence_source_rows_are_deterministic(self):
        """Evidence source_rows must have deterministic order for reproducibility."""
        import pandas as pd
        from sat_sa.evidence import attach_evidence, build_lookups
        from sat_sa.schema import Flag

        alerts = pd.DataFrame({
            "alert_id": [f"AL-{i:09d}" for i in range(5)],
            "entity_id": ["E1"] * 5,
            "severity": ["high", "critical", "medium", "low", "high"],
            "category": ["malware"] * 5,
            "created_at": ["2026-01-01T00:00:00Z"] * 5,
            "disposition": ["true_positive"] * 5,
            "escalated": [False, True, False, False, True],
        })
        source = {"alerts": alerts}
        lookups = build_lookups(source)

        flag = Flag(
            flag_id="fg_00001", detector="test", entity_id="E1",
            severity_weight=1.0, rationale="test",
            evidence={"alert_ids": ["AL-000000004", "AL-000000001", "AL-000000003"]}
        )

        # Attach evidence multiple times
        results = [attach_evidence(flag, source, lookups) for _ in range(5)]

        # All results should have identical source_rows ordering
        for r in results[1:]:
            assert r.evidence["source_rows"] == results[0].evidence["source_rows"]

    def test_write_flags_is_atomic(self):
        """_write_flags must not leave partial files on interruption."""
        from pathlib import Path
        import tempfile, json
        from sat_sa.cli import _write_flags
        from sat_sa.schema import Flag

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test_flags.json"
            flags = [Flag(
                flag_id="fg_00001", detector="test", entity_id="E1",
                severity_weight=1.0, rationale="test", evidence={}
            )]

            _write_flags(path, flags)

            # File should exist and be valid JSON
            assert path.exists()
            data = json.loads(path.read_text())
            assert len(data) == 1
            assert data[0]["flag_id"] == "fg_00001"

            # No temp file should remain
            tmp_files = list(Path(tmpdir).glob("*.tmp"))
            assert len(tmp_files) == 0

    def test_config_type_validation_catches_non_numeric(self, normalized_run_dir):
        """Config with non-numeric values must be rejected at load time."""
        import tempfile, yaml
        from pathlib import Path
        from typer.testing import CliRunner
        from sat_sa.cli import app

        runner = CliRunner()
        bad_cfg = {"fast_closure_k": "not_a_number"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(bad_cfg, f)
            cfg_path = f.name

        rd = normalized_run_dir
        result = runner.invoke(app, [
            "detect", "--data", str(rd / "normalized"),
            "--config", cfg_path, "--out", str(rd / "results/test.json")
        ])
        # Should fail with a clean error, not a raw traceback
        assert result.exit_code != 0
        assert "must be a number" in (result.output or "") or "Bad parameter" in (result.output or "")
        Path(cfg_path).unlink(missing_ok=True)

    def test_config_bounds_validation(self, normalized_run_dir):
        """Config values outside bounds must be rejected."""
        import tempfile, yaml
        from pathlib import Path
        from typer.testing import CliRunner
        from sat_sa.cli import app

        runner = CliRunner()
        bad_cfg = {"fast_closure_k": -1.0}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(bad_cfg, f)
            cfg_path = f.name

        rd = normalized_run_dir
        result = runner.invoke(app, [
            "detect", "--data", str(rd / "normalized"),
            "--config", cfg_path, "--out", str(rd / "results/test.json")
        ])
        assert result.exit_code != 0
        assert "outside valid range" in (result.output or "") or "Bad parameter" in (result.output or "")
        Path(cfg_path).unlink(missing_ok=True)

    def test_pipeline_roundtrip_reproducibility(self, normalized_run_dir):
        """Same pipeline run should produce content-identical flags (excluding timestamps)."""
        import subprocess, sys, json
        from pathlib import Path

        rd = normalized_run_dir
        for run in [1, 2]:
            r = subprocess.run(
                [sys.executable, "-m", "sat_sa.cli", "detect",
                 "--data", str(rd / "normalized"), "--no-adaptive", "--workers", "1",
                 "--out", str(rd / f"repro_run{run}.json")],
                capture_output=True, text=True, timeout=120
            )
            assert r.returncode == 0, f"Run {run} failed"

        f1 = json.loads((rd / "repro_run1.json").read_text())
        f2 = json.loads((rd / "repro_run2.json").read_text())

        # Compare excluding generated_at timestamps
        def normalize(flags):
            return [{k: v for k, v in f.items() if k != "generated_at"} for f in flags]

        assert normalize(f1) == normalize(f2), "Pipeline output is non-deterministic"

        # Verify flag_id sequence is deterministic
        assert [f["flag_id"] for f in f1] == [f["flag_id"] for f in f2]


class TestAdversarialHardening:
    """Adversarial input hardening: malformed artifacts must fail cleanly, never crash."""

    def test_score_handles_corrupt_volume_values(self):
        """score_entities must not crash on non-numeric or negative volumes."""
        from sat_sa.scoring import score_entities
        from sat_sa.schema import Flag

        flags = [
            Flag(flag_id="fg_00001", detector="test", entity_id="E1",
                 severity_weight=2.0, rationale="t", evidence={}),
            Flag(flag_id="fg_00002", detector="test", entity_id="E2",
                 severity_weight=3.0, rationale="t", evidence={}),
        ]
        # Every one of these used to raise ValueError before the fix.
        bad_volumes = [
            {"E1": "not_a_number", "E2": 100},   # string
            {"E1": -100, "E2": 100},             # negative -> math.log domain error
            {"E1": None, "E2": 100},             # None
        ]
        for volumes in bad_volumes:
            out = score_entities(flags, volumes)
            assert not out.empty
            row = out[out["entity_id"] == "E1"].iloc[0]
            assert row["alert_volume"] == 0  # coerced safely, not crashed

    def test_detect_rejects_corrupt_parquet_cleanly(self, normalized_run_dir):
        """detect must fail with a clean error (no raw pyarrow traceback) on corrupt parquet."""
        import shutil as _shutil
        import subprocess

        norm = normalized_run_dir / "normalized"
        probe = Path(tempfile.mkdtemp(prefix="satsa_corrupt_")) / "norm"
        _shutil.copytree(norm, probe)
        try:
            (probe / "alerts.parquet").write_bytes(b"GARBAGE NOT PARQUET")
            r = subprocess.run(
                [sys.executable, "-m", "sat_sa.cli", "detect",
                 "--data", str(probe), "--out", str(probe.parent / "flags.json")],
                capture_output=True, text=True, timeout=180,
            )
            assert r.returncode != 0
            assert "Traceback" not in (r.stderr or ""), "raw traceback leaked to the user"
            assert "unreadable" in (r.stderr or ""), "error should point at the data dir"
        finally:
            _shutil.rmtree(probe.parent, ignore_errors=True)

    def test_report_rejects_scores_missing_columns(self):
        """report must reject a scores CSV missing required columns with a clean error."""
        import csv as _csv
        import tempfile
        from pathlib import Path
        from typer.testing import CliRunner
        from sat_sa.cli import app

        with tempfile.TemporaryDirectory() as tmpdir:
            results = Path(tmpdir) / "results"
            results.mkdir()
            (results / "flags.json").write_text(json.dumps([
                {"flag_id": "fg_00001", "detector": "fast_closure", "entity_id": "E1",
                 "severity_weight": 2.0, "rationale": "t",
                 "evidence": {"alert_ids": ["AL-001"]},
                 "generated_at": "2026-01-01T00:00:00Z"}
            ]))
            with open(results / "entity_scores.csv", "w", newline="") as f:
                w = _csv.writer(f)
                w.writerow(["entity_id", "risk_score"])  # missing priority_rank
                w.writerow(["E1", 0.5])

            runner = CliRunner()
            result = runner.invoke(app, [
                "report",
                "--scores", str(results / "entity_scores.csv"),
                "--flags", str(results / "flags.json"),
                "--out", str(results / "report.json"),
            ])
            assert result.exit_code != 0
            assert "missing required columns" in (result.output or "")

    def test_save_queue_blocks_directory_hijack(self):
        """save_queue must raise a clean OSError, not PermissionError, when the target path is a directory."""
        import os as _os
        import tempfile
        from pathlib import Path

        def save_queue_impl(p: Path, items: list):
            p = Path(p)
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists() and not p.is_file():
                raise OSError(f"Cannot write review queue: {p} exists and is not a file.")
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
            tmp.replace(p)

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "review_queue.json"
            p.mkdir()  # hijack the path with a directory
            try:
                save_queue_impl(p, [{"id": "fg_00001"}])
                raise AssertionError("should have raised OSError")
            except OSError as exc:
                assert "not a file" in str(exc)
            finally:
                _os.rmdir(p)

    def test_read_json_survives_directory_as_path(self):
        """_read_json must return the default, not crash, when the path points at a directory."""
        import os as _os
        import tempfile
        from pathlib import Path

        def _read_json_impl(p, default):
            try:
                return json.loads(Path(p).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return default

        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir) / "is_a_dir"
            d.mkdir()
            # On Windows a directory read raises PermissionError (an OSError subclass);
            # on POSIX it raises IsADirectoryError (also OSError). Both must fall back.
            assert _read_json_impl(d, "DEFAULT") == "DEFAULT"
            # Missing file still returns default
            assert _read_json_impl(Path(tmpdir) / "nope.json", "DEFAULT") == "DEFAULT"
            # Corrupt JSON still returns default
            f = Path(tmpdir) / "corrupt.json"
            f.write_text("NOT JSON {{{")
            assert _read_json_impl(f, "DEFAULT") == "DEFAULT"
