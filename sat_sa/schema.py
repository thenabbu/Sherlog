"""Validated, serialisable records shared by ingestion, detectors and reports."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Criticality(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Disposition(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign = "benign"
    unresolved = "unresolved"


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", use_enum_values=True)


class Entity(StrictRecord):
    entity_id: str
    name: str
    peer_group: str
    sector: str | None = None


class Asset(StrictRecord):
    asset_id: str
    entity_id: str
    criticality: Criticality
    asset_type: str | None = None


class Alert(StrictRecord):
    alert_id: str
    entity_id: str
    asset_id: str | None = None
    category: str
    severity: Severity
    created_at: datetime
    first_ack_at: datetime | None = None
    closed_at: datetime | None = None
    disposition: Disposition
    escalated: bool
    escalated_at: datetime | None = None
    case_id: str | None = None

    @model_validator(mode="after")
    def chronology_is_valid(self) -> "Alert":
        if self.closed_at and self.closed_at < self.created_at:
            raise ValueError("closed_at must not precede created_at")
        if self.escalated_at and self.escalated_at < self.created_at:
            raise ValueError("escalated_at must not precede created_at")
        return self


class Case(StrictRecord):
    case_id: str
    entity_id: str
    opened_at: datetime
    closed_at: datetime | None = None
    alert_ids: list[str]
    root_cause_documented: bool


class Escalation(StrictRecord):
    escalation_id: str
    alert_id: str
    escalated_at: datetime
    escalated_to_tier: str


class Flag(BaseModel):
    """One self-contained supervisory finding with immutable source references."""

    flag_id: str
    detector: str
    entity_id: str
    severity_weight: float
    rationale: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def as_json(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


SCHEMAS: dict[str, type[BaseModel]] = {
    "entities": Entity,
    "assets": Asset,
    "alerts": Alert,
    "cases": Case,
    "escalations": Escalation,
}
