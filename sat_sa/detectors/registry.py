"""Shared detector metadata used by the CLI, scoring and presentation layers."""

from __future__ import annotations

DETECTOR_REGISTRY = {
    "fast_closure": dict(rule="D1 · fast_closure", name="Unusually fast closure of high/critical alerts", desc="High/critical severity alerts closed extraordinarily quickly versus the submission's closure distribution for that severity.", method="Statistical outlier — severity-specific Q1 − k × IQR lower fence", capability="Investigation", family="EG", weight=2),
    "no_escalation": dict(rule="D2 · no_escalation", name="Critical true-positive closed without escalation", desc="Deterministic process/control inconsistency: critical severity, true positive, no recorded escalation.", method="Deterministic rule (no statistical baseline)", capability="Escalation", family="EG", weight=3),
    "low_coverage": dict(rule="D3 · low_coverage", name="Low critical-asset coverage vs peers", desc="Critical asset generating unusually few alerts versus the peer-group median for critical assets (possible monitoring blind spot).", method="Peer cohort comparison — configured window vs cohort median", capability="Detection", family="NS", weight=2),
    "ack_without_meaningful_investigation": dict(rule="E1 · ack_without_meaningful_investigation", name="Acknowledged alert without meaningful investigation", desc="A high/critical alert is acknowledged and linked to a case, but the case does not document a root cause.", method="Relationship completeness — acknowledgement + case + root-cause evidence", capability="Investigation", family="EG", weight=2),
    "short_investigation": dict(rule="E4 · short_investigation", name="Unusually short investigation", desc="A high/critical alert is linked to a case whose open-to-close duration is unusually short for its peer cohort.", method="Peer outlier — case duration Q1 − k × IQR lower fence", capability="Investigation", family="EG", weight=2),
    "investigation_closure_mismatch": dict(rule="E5 · investigation_closure_mismatch", name="True-positive closure without root-cause evidence", desc="A high/critical true-positive alert is closed through a case that lacks documented root cause.", method="Relationship completeness — disposition + closed case + root-cause evidence", capability="Investigation", family="EG", weight=2),
    "recurrence_without_root_cause": dict(rule="E8 · recurrence_without_root_cause", name="Repeated asset alerts without root-cause evidence", desc="The same asset receives repeated alerts while associated cases do not document root cause.", method="Entity/asset recurrence with case evidence check", capability="Remediation", family="EG", weight=2),
    "workload_severity_mismatch": dict(rule="E11 · workload_severity_mismatch", name="Severity workload inconsistent with case workload", desc="High/critical true-positive workload is materially larger than the entity's case workload relative to peers.", method="Peer comparison of high/critical alert-to-case workload ratio", capability="Governance & oversight", family="EG", weight=2),
    "high_risk_no_escalation": dict(rule="E9 · high_risk_no_escalation", name="High-severity true-positive without escalation", desc="A high-severity true-positive alert has no recorded escalation; critical-only D2 remains separate.", method="Deterministic severity/escalation mismatch", capability="Escalation", family="EG", weight=2),
    "critical_asset_no_telemetry": dict(rule="N1 · critical_asset_no_telemetry", name="Critical asset with no telemetry evidence", desc="A critical asset has zero observed alerts while comparable critical assets have positive activity.", method="Peer baseline with positive comparison guard", capability="Detection", family="NS", weight=2),
    "missing_investigation_evidence": dict(rule="N3 · missing_investigation_evidence", name="Alert without investigation evidence", desc="A high/critical alert has no matching case record.", method="Alert-to-case relationship completeness", capability="Investigation", family="NS", weight=2),
    "missing_escalation_evidence": dict(rule="N4 · missing_escalation_evidence", name="Escalation claim without escalation record", desc="An alert is marked escalated but no matching escalation record is present.", method="Alert-to-escalation relationship completeness", capability="Escalation", family="NS", weight=2),
    "low_entity_activity": dict(rule="N7 · low_entity_activity", name="Entity activity materially below peers", desc="An entity's alert activity is materially below its peer-group median with a positive comparison baseline.", method="Peer cohort comparison with minimum sample guard", capability="Detection", family="NS", weight=2),
}

GROUP_DETECTORS = {
    "execution_gaps": [name for name, meta in DETECTOR_REGISTRY.items() if meta["family"] == "EG"],
    "negative_space": [name for name, meta in DETECTOR_REGISTRY.items() if meta["family"] == "NS"],
}

