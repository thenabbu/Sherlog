from __future__ import annotations

import pandas as pd

from sat_sa.schema import Flag


def attach_evidence(flag: Flag, source_records: dict[str, pd.DataFrame]) -> Flag:
    """Embed compact, JSON-safe source rows referenced by a finding for drill-down."""
    evidence = dict(flag.evidence)
    rows: list[dict] = []
    alert_ids = set(evidence.get("alert_ids", []))
    asset_ids = set(evidence.get("asset_ids", []))
    if alert_ids and "alerts" in source_records:
        rows.extend(source_records["alerts"].loc[source_records["alerts"].alert_id.isin(alert_ids)].to_dict("records"))
    if asset_ids and "assets" in source_records:
        rows.extend(source_records["assets"].loc[source_records["assets"].asset_id.isin(asset_ids)].to_dict("records"))
    if rows:
        evidence["source_rows"] = [{key: (value.isoformat() if hasattr(value, "isoformat") else value) for key, value in row.items()} for row in rows]
    return flag.model_copy(update={"evidence": evidence})
