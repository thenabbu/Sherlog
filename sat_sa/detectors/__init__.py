from .execution_gaps import (detect_ack_without_meaningful_investigation,
                             detect_critical_no_escalation, detect_fast_closure,
                             detect_high_risk_no_escalation,
                             detect_investigation_closure_mismatch,
                             detect_recurrence_without_root_cause,
                             detect_short_investigation,
                             detect_workload_severity_mismatch)
from .negative_space import (detect_critical_asset_no_telemetry,
                             detect_low_critical_asset_coverage,
                             detect_low_critical_asset_coverage_from_counts,
                             detect_low_entity_activity,
                             detect_missing_escalation_evidence,
                             detect_missing_investigation_evidence)
from .registry import DETECTOR_REGISTRY, GROUP_DETECTORS

__all__ = ["detect_fast_closure", "detect_critical_no_escalation", "detect_low_critical_asset_coverage", "detect_low_critical_asset_coverage_from_counts", "detect_ack_without_meaningful_investigation", "detect_short_investigation", "detect_investigation_closure_mismatch", "detect_recurrence_without_root_cause", "detect_workload_severity_mismatch", "detect_high_risk_no_escalation", "detect_critical_asset_no_telemetry", "detect_missing_investigation_evidence", "detect_missing_escalation_evidence", "detect_low_entity_activity", "DETECTOR_REGISTRY", "GROUP_DETECTORS"]
