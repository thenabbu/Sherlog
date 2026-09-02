from __future__ import annotations

import pandas as pd

from sat_sa.detectors.execution_gaps import (
    detect_ack_without_meaningful_investigation,
    detect_high_risk_no_escalation,
    detect_investigation_closure_mismatch,
    detect_recurrence_without_root_cause,
    detect_short_investigation,
)
from sat_sa.detectors.negative_space import (
    detect_critical_asset_no_telemetry,
    detect_low_entity_activity,
    detect_missing_escalation_evidence,
    detect_missing_investigation_evidence,
)


def alerts(rows):
    return pd.DataFrame(rows, columns=["alert_id", "entity_id", "asset_id", "severity", "created_at", "first_ack_at", "closed_at", "disposition", "escalated", "case_id"])


def test_relationship_and_severity_rules():
    frame = alerts([
        ["A1", "E1", "AS1", "high", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "2026-01-01T01:00:00Z", "true_positive", False, "C1"],
        ["A2", "E1", "AS2", "high", "2026-01-01T00:00:00Z", None, "2026-01-01T01:00:00Z", "true_positive", False, None],
    ])
    cases = pd.DataFrame([["C1", "E1", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", ["A1"], False]], columns=["case_id", "entity_id", "opened_at", "closed_at", "alert_ids", "root_cause_documented"])
    assert {f.detector for f in detect_ack_without_meaningful_investigation(frame, cases)} == {"ack_without_meaningful_investigation"}
    assert {f.detector for f in detect_investigation_closure_mismatch(frame, cases)} == {"investigation_closure_mismatch"}
    assert {f.detector for f in detect_high_risk_no_escalation(frame)} == {"high_risk_no_escalation"}
    assert {f.detector for f in detect_missing_investigation_evidence(frame, {"C1"})} == {"missing_investigation_evidence"}


def test_short_investigation_requires_peer_sample():
    entities = pd.DataFrame([[f"E{i}", "P"] for i in range(4)], columns=["entity_id", "peer_group"])
    cases = pd.DataFrame([[f"C{i}", f"E{i}", "2026-01-01T00:00:00Z", f"2026-01-01T0{i+1}:00:00Z", [], True] for i in range(4)], columns=["case_id", "entity_id", "opened_at", "closed_at", "alert_ids", "root_cause_documented"])
    frame = alerts([["A0", "E0", "AS1", "high", "2026-01-01T00:00:00Z", None, "2026-01-01T01:00:00Z", "true_positive", True, "C0"]])
    assert detect_short_investigation(frame, cases, entities, k=1.5, min_peer_sample=4) == []


def test_recurrence_requires_minimum_and_no_root_cause():
    frame = alerts([[f"A{i}", "E1", "AS1", "medium", f"2026-01-0{i+1}T00:00:00Z", None, None, "true_positive", False, None] for i in range(3)])
    flags = detect_recurrence_without_root_cause(frame, pd.DataFrame(), min_alerts=3)
    assert len(flags) == 1
    assert flags[0].evidence["repeat_count"] == 3


def test_negative_space_guards_positive_peer_baselines():
    entities = pd.DataFrame([[f"E{i}", "P"] for i in range(4)], columns=["entity_id", "peer_group"])
    assets = pd.DataFrame([[f"AS{i}", f"E{i}", "critical"] for i in range(4)], columns=["asset_id", "entity_id", "criticality"])
    counts = pd.DataFrame([["E1", "AS1", 4], ["E2", "AS2", 4], ["E3", "AS3", 4]], columns=["entity_id", "asset_id", "observed_count"])
    assert len(detect_critical_asset_no_telemetry(counts, assets, pd.Timestamp("2026-01-01", tz="UTC"))) == 1
    activity = pd.DataFrame([["E0", 0], ["E1", 4], ["E2", 4], ["E3", 4]], columns=["entity_id", "alert_count"])
    assert len(detect_low_entity_activity(activity, entities, threshold_pct=.25, min_peer_sample=4)) == 1


def test_missing_escalation_evidence_only_flags_claimed_records():
    frame = alerts([["A1", "E1", "AS1", "critical", "2026-01-01T00:00:00Z", None, None, "true_positive", True, None]])
    assert len(detect_missing_escalation_evidence(frame, set())) == 1
    assert detect_missing_escalation_evidence(frame, {"A1"}) == []
