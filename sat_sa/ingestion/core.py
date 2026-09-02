"""Input adapters. Validation failures are returned to callers, never discarded."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
from pydantic import ValidationError

from sat_sa.schema import SCHEMAS


@dataclass
class RawTable:
    frame: pd.DataFrame
    source: str
    table_name: str | None = None


@dataclass
class FieldMapping:
    table_name: str
    columns: dict[str, str] = field(default_factory=dict)


def load_csv(path: str | Path, entity_hint: str | None = None) -> RawTable:
    frame = pd.read_csv(path)
    if entity_hint and "entity_id" not in frame.columns:
        frame["entity_id"] = entity_hint
    return RawTable(frame=frame, source=str(path), table_name=Path(path).stem.replace("_ground_truth", ""))


def load_json(path: str | Path) -> RawTable:
    with Path(path).open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        # A named-table export may contain one table; flatten it predictably.
        if len(payload) == 1 and isinstance(next(iter(payload.values())), list):
            name, payload = next(iter(payload.items()))
            return RawTable(pd.DataFrame(payload), str(path), name)
        payload = [payload]
    return RawTable(pd.DataFrame(payload), str(path), Path(path).stem)


def normalize(raw: RawTable, mapping: FieldMapping) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    """Map and Pydantic-validate every input row, preserving rejects with reasons."""
    if mapping.table_name not in SCHEMAS:
        raise ValueError(f"Unsupported table '{mapping.table_name}'. Expected one of {sorted(SCHEMAS)}")
    frame = raw.frame.rename(columns=mapping.columns).copy()
    valid: list[dict[str, Any]] = []
    rejects: list[dict[str, Any]] = []
    model = SCHEMAS[mapping.table_name]
    for index, row in frame.iterrows():
        # Streaming CSV parsing preserves empty cells as empty strings whereas
        # pandas' default parser represents them as NaN. Treat both uniformly.
        data = {key: (None if pd.isna(value) or (isinstance(value, str) and not value.strip()) else value) for key, value in row.to_dict().items()}
        # CSV represents case alert lists as JSON. Invalid JSON will be reported as a reject.
        if mapping.table_name == "cases" and isinstance(data.get("alert_ids"), str):
            try:
                data["alert_ids"] = json.loads(data["alert_ids"])
            except json.JSONDecodeError:
                pass
        try:
            valid.append(model.model_validate(data).model_dump(mode="json"))
        except ValidationError as exc:
            rejects.append({"source": raw.source, "table": mapping.table_name, "row": int(index),
                            "reason": exc.errors(include_url=False), "record": data})
    return pd.DataFrame(valid), rejects


def normalize_table(path: str | Path, input_format: str, table_name: str | None = None) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    raw = load_csv(path) if input_format == "csv" else load_json(path)
    name = table_name or raw.table_name or Path(path).stem
    return normalize(raw, FieldMapping(table_name=name))
