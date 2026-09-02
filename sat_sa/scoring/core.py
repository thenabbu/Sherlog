from __future__ import annotations

import json
import math

import pandas as pd

from sat_sa.schema import Flag
from sat_sa.detectors.registry import DETECTOR_REGISTRY


DEFAULT_WEIGHTS = {name: meta["weight"] for name, meta in DETECTOR_REGISTRY.items()}


def score_entities(flags: list[Flag], alert_volume_by_entity: dict[str, int], weights: dict[str, float] | None = None) -> pd.DataFrame:
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    entities = set(alert_volume_by_entity) | {flag.entity_id for flag in flags}
    records = []
    for entity_id in entities:
        own_flags = [flag for flag in flags if flag.entity_id == entity_id]
        counts: dict[str, int] = {}
        for flag in own_flags:
            counts[flag.detector] = counts.get(flag.detector, 0) + 1
        volume = int(alert_volume_by_entity.get(entity_id, 0))
        numerator = sum(weights.get(detector, 1) * count for detector, count in counts.items())
        records.append({"entity_id": entity_id, "risk_score": numerator / math.log(1 + volume) if volume else float(numerator),
                        "alert_volume": volume, "flag_count_by_detector": json.dumps(counts, sort_keys=True),
                        "distinct_detectors_triggered": len(counts)})
    out = pd.DataFrame(records)
    if out.empty:
        return pd.DataFrame(columns=["entity_id", "risk_score", "priority_rank", "flag_count_by_detector", "distinct_detectors_triggered"])
    out = out.sort_values(["risk_score", "distinct_detectors_triggered", "entity_id"], ascending=[False, False, True]).reset_index(drop=True)
    out["risk_score"] = out["risk_score"].round(4)
    out["priority_rank"] = out.index + 1
    return out[["entity_id", "risk_score", "priority_rank", "flag_count_by_detector", "distinct_detectors_triggered", "alert_volume"]]
