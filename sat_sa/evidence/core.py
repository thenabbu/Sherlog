from __future__ import annotations

import pandas as pd

from sat_sa.schema import Flag


def attach_evidence(flag: Flag, source_records: dict[str, pd.DataFrame]) -> Flag:
    """Embed compact, JSON-safe source rows referenced by a finding for drill-down."""
    evidence = dict(flag.evidence)
    rows: list[dict] = []
    alert_ids = set(evidence.get("alert_ids", []))
    asset_ids = set(evidence.get("asset_ids", []))
    case_ids = set(evidence.get("case_ids", []))
    escalation_ids = set(evidence.get("escalation_ids", []))
    if alert_ids and "alerts" in source_records:
        rows.extend(source_records["alerts"].loc[source_records["alerts"].alert_id.isin(alert_ids)].to_dict("records"))
    if asset_ids and "assets" in source_records:
        rows.extend(source_records["assets"].loc[source_records["assets"].asset_id.isin(asset_ids)].to_dict("records"))
    if case_ids and "cases" in source_records:
        rows.extend(source_records["cases"].loc[source_records["cases"].case_id.isin(case_ids)].to_dict("records"))
    if escalation_ids and "escalations" in source_records:
        rows.extend(source_records["escalations"].loc[source_records["escalations"].escalation_id.isin(escalation_ids)].to_dict("records"))
    if rows:
        def json_safe(value):
            if hasattr(value, "isoformat"):
                return value.isoformat()
            if hasattr(value, "tolist"):
                return value.tolist()
            return value.item() if hasattr(value, "item") else value
        evidence["source_rows"] = [{key: json_safe(value) for key, value in row.items()} for row in rows]
    return flag.model_copy(update={"evidence": evidence})
