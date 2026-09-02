import pandas as pd
import pyarrow.parquet as pq

from sat_sa.detectors import detect_critical_no_escalation, detect_fast_closure, detect_low_critical_asset_coverage
from sat_sa.ingestion import FieldMapping, RawTable, normalize
from sat_sa.scoring import score_entities
from sat_sa.synth import generate, write_synthetic
import sat_sa.runtime as runtime
from sat_sa.runtime import AdaptiveController, RuntimeSettings, SystemProfile, choose_runtime_settings


def test_synthetic_injections_are_detected():
    frames = generate(n_entities=10, alerts_per_entity=50, seed=7, anomaly_rate=.2)
    assets = frames["assets"].merge(frames["entities"][["entity_id", "peer_group"]], on="entity_id")
    found = (detect_fast_closure(frames["alerts"]), detect_critical_no_escalation(frames["alerts"]), detect_low_critical_asset_coverage(frames["alerts"], assets))
    assert all(flags for flags in found)


def test_invalid_rows_are_audited_not_dropped_silently():
    raw = RawTable(pd.DataFrame([{"alert_id": "bad"}]), "test.csv")
    valid, rejects = normalize(raw, FieldMapping("alerts"))
    assert valid.empty and len(rejects) == 1 and rejects[0]["row"] == 0


def test_score_ranks_detector_diversity_when_scores_tie():
    frames = generate(n_entities=4, alerts_per_entity=10, seed=1, anomaly_rate=.25)
    flags = detect_critical_no_escalation(frames["alerts"])
    scores = score_entities(flags, {"CSE-001": 10, "CSE-002": 10})
    assert "priority_rank" in scores and scores.priority_rank.iloc[0] == 1


def test_streaming_generator_writes_bounded_batches(tmp_path):
    stats = write_synthetic(tmp_path, n_entities=4, alerts_per_entity=25, seed=3, anomaly_rate=.25, batch_size=7)
    assert stats["alerts"] == 102
    assert pq.ParquetFile(tmp_path / "alerts.parquet").metadata.num_rows == 102


def test_runtime_tuner_honours_explicit_limits():
    settings = choose_runtime_settings(batch_size=1234, workers=2)
    assert settings.batch_size == 1234 and settings.workers == 2


def test_adaptive_controller_keeps_explicit_small_batch_floor():
    controller = AdaptiveController(choose_runtime_settings(batch_size=7, workers=1))
    assert controller.min_batch_size == 7


def test_adaptive_controller_scales_up_and_down(monkeypatch):
    settings = RuntimeSettings(10_000, 1, SystemProfile(8, 16_384, 32_768, "nt"))
    controller = AdaptiveController(settings, check_every_batches=1)
    monkeypatch.setattr(runtime, "_cpu_times", lambda: None)
    monkeypatch.setattr(runtime, "detect_system", lambda: SystemProfile(8, 16_384, 32_768, "nt"))
    increase = controller.after_batch()
    assert increase and increase.new_batch_size > 10_000 and increase.new_workers > 1
    monkeypatch.setattr(runtime, "detect_system", lambda: SystemProfile(8, 400, 32_768, "nt"))
    decrease = controller.after_batch()
    assert decrease and decrease.new_batch_size < increase.new_batch_size and decrease.new_workers < increase.new_workers
