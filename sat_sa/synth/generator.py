"""Deterministic synthetic submissions with detector-blind ground truth."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


class _BatchWriter:
    """Append matching CSV and parquet files without retaining previous batches."""

    def __init__(self, out: Path, name: str):
        self.csv_path = out / f"{name}.csv"
        self.parquet_path = out / f"{name}.parquet"
        self.writer: pq.ParquetWriter | None = None
        self.schema = pa.schema([
            pa.field("alert_id", pa.string()), pa.field("entity_id", pa.string()), pa.field("asset_id", pa.string()),
            pa.field("category", pa.string()), pa.field("severity", pa.string()), pa.field("created_at", pa.string()),
            pa.field("first_ack_at", pa.string()), pa.field("closed_at", pa.string()), pa.field("disposition", pa.string()),
            pa.field("escalated", pa.bool_()), pa.field("escalated_at", pa.string()), pa.field("case_id", pa.string()),
        ])

    def write(self, frame: pd.DataFrame) -> None:
        if frame.empty:
            return
        frame.to_csv(self.csv_path, mode="a", index=False, header=not self.csv_path.exists())
        table = pa.Table.from_pandas(frame, schema=self.schema, preserve_index=False)
        if self.writer is None:
            self.writer = pq.ParquetWriter(self.parquet_path, table.schema, compression="snappy")
        self.writer.write_table(table)

    def close(self) -> None:
        if self.writer:
            self.writer.close()


def _truth_for_alert(truth: list[dict], alert: dict, case_root_cause: bool | None = None) -> None:
    """Record deterministic truth for rules whose evidence is in one alert/relationship."""
    severity = alert.get("severity")
    if severity in {"high", "critical"} and alert.get("case_id") is None:
        truth.append({"detector": "missing_investigation_evidence", "entity_id": alert["entity_id"], "alert_id": alert["alert_id"], "asset_id": None})
    if severity == "high" and alert.get("disposition") == "true_positive" and not alert.get("escalated"):
        truth.append({"detector": "high_risk_no_escalation", "entity_id": alert["entity_id"], "alert_id": alert["alert_id"], "asset_id": None})
    if alert.get("escalated"):
        truth.append({"detector": "missing_escalation_evidence", "entity_id": alert["entity_id"], "alert_id": alert["alert_id"], "asset_id": None})
    if case_root_cause is False and severity in {"high", "critical"} and alert.get("first_ack_at"):
        truth.append({"detector": "ack_without_meaningful_investigation", "entity_id": alert["entity_id"], "alert_id": alert["alert_id"], "asset_id": None})
        if alert.get("disposition") == "true_positive" and alert.get("closed_at"):
            truth.append({"detector": "investigation_closure_mismatch", "entity_id": alert["entity_id"], "alert_id": alert["alert_id"], "asset_id": None})


def generate(n_entities: int = 25, alerts_per_entity: int = 400, seed: int = 42, anomaly_rate: float = .15) -> dict[str, pd.DataFrame]:
    if n_entities < 4:
        raise ValueError("At least 4 entities are required to form meaningful peer cohorts")
    rng = np.random.default_rng(seed)
    entities, assets, alerts, cases, escalations, truth = [], [], [], [], [], []
    reference = datetime(2026, 8, 30, 12, tzinfo=timezone.utc)
    anomaly_count = max(1, round(n_entities * anomaly_rate))
    pools = {detector: set(rng.choice(np.arange(n_entities), size=anomaly_count, replace=False)) for detector in ("fast_closure", "no_escalation", "low_coverage")}
    alert_number = 0
    for entity_idx in range(n_entities):
        entity_id = f"CSE-{entity_idx + 1:03d}"
        case_id = f"CASE-{entity_idx + 1:03d}"
        peer_group = "finserv-tier2" if entity_idx % 2 == 0 else "energy-tier2"
        entities.append({"entity_id": entity_id, "name": f"Synthetic CSE {entity_idx + 1}", "peer_group": peer_group, "sector": "financial" if entity_idx % 2 == 0 else "energy"})
        own_assets = []
        for asset_idx in range(3):
            asset_id = f"AST-{entity_idx+1:03d}-{asset_idx+1}"
            criticality = "critical" if asset_idx < 2 else "high"
            asset = {"asset_id": asset_id, "entity_id": entity_id, "criticality": criticality, "asset_type": "payment gateway" if asset_idx == 0 else "domain controller"}
            assets.append(asset); own_assets.append(asset)
        low_asset = own_assets[0]["asset_id"]
        candidates = [asset["asset_id"] for asset in own_assets if not (entity_idx in pools["low_coverage"] and asset["asset_id"] == low_asset)]
        first_alert = None
        for _ in range(alerts_per_entity):
            alert_number += 1
            created = reference - timedelta(minutes=int(rng.integers(0, 29 * 24 * 60)))
            severity = rng.choice(["low", "medium", "high", "critical"], p=[.35, .35, .22, .08]).item()
            # A realistic, moderately tight baseline makes very fast closures genuine
            # IQR lower-fence outliers rather than an artifact of a broad uniform range.
            duration = int(np.clip(rng.normal(480, 35), 420, 600)) if severity in {"high", "critical"} else int(rng.integers(60, 600))
            disposition = rng.choice(["true_positive", "false_positive", "benign", "unresolved"], p=[.22, .35, .35, .08]).item()
            # Keep non-injected critical true positives compliant so validation has a
            # precise, known negative population for the no-escalation detector.
            escalated = bool(severity == "critical" and disposition == "true_positive")
            alert_id = f"AL-{alert_number:09d}"
            alert = {"alert_id": alert_id, "entity_id": entity_id, "asset_id": rng.choice(candidates).item(), "category": rng.choice(["malware", "intrusion", "phishing", "DoS"]).item(),
                "severity": severity, "created_at": created.isoformat(), "first_ack_at": (created + timedelta(minutes=5)).isoformat(), "closed_at": (created + timedelta(minutes=duration)).isoformat(),
                "disposition": disposition, "escalated": escalated, "escalated_at": (created + timedelta(minutes=30)).isoformat() if escalated else None, "case_id": None}
            if first_alert is None:
                first_alert = alert
                alert["case_id"] = case_id
            else:
                _truth_for_alert(truth, alert)
            alerts.append(alert)
        cases.append({"case_id": case_id, "entity_id": entity_id,
                      "opened_at": first_alert["created_at"],
                      "closed_at": first_alert["closed_at"],
                      "alert_ids": [first_alert["alert_id"]],
                      "root_cause_documented": first_alert["disposition"] == "true_positive"})
        _truth_for_alert(truth, first_alert, first_alert["disposition"] == "true_positive")
        if entity_idx in pools["fast_closure"]:
            alert_number += 1; created = reference - timedelta(hours=1); alert_id = f"AL-{alert_number:09d}"
            injected = {"alert_id": alert_id, "entity_id": entity_id, "asset_id": own_assets[1]["asset_id"], "category": "intrusion", "severity": "high", "created_at": created.isoformat(), "first_ack_at": created.isoformat(), "closed_at": (created + timedelta(minutes=2)).isoformat(), "disposition": "true_positive", "escalated": True, "escalated_at": (created + timedelta(minutes=1)).isoformat(), "case_id": None}
            alerts.append(injected); _truth_for_alert(truth, injected)
            truth.append({"detector": "fast_closure", "entity_id": entity_id, "alert_id": alert_id, "asset_id": None})
        if entity_idx in pools["no_escalation"]:
            alert_number += 1; created = reference - timedelta(hours=2); alert_id = f"AL-{alert_number:09d}"
            injected = {"alert_id": alert_id, "entity_id": entity_id, "asset_id": own_assets[1]["asset_id"], "category": "malware", "severity": "critical", "created_at": created.isoformat(), "first_ack_at": created.isoformat(), "closed_at": (created + timedelta(hours=8)).isoformat(), "disposition": "true_positive", "escalated": False, "escalated_at": None, "case_id": None}
            alerts.append(injected); _truth_for_alert(truth, injected)
            truth.append({"detector": "no_escalation", "entity_id": entity_id, "alert_id": alert_id, "asset_id": None})
        if entity_idx in pools["low_coverage"]:
            truth.append({"detector": "low_coverage", "entity_id": entity_id, "alert_id": None, "asset_id": low_asset})
    return {"entities": pd.DataFrame(entities), "assets": pd.DataFrame(assets), "alerts": pd.DataFrame(alerts), "cases": pd.DataFrame(cases, columns=["case_id", "entity_id", "opened_at", "closed_at", "alert_ids", "root_cause_documented"]), "escalations": pd.DataFrame(escalations, columns=["escalation_id", "alert_id", "escalated_at", "escalated_to_tier"]), "ground_truth": pd.DataFrame(truth)}


def write_synthetic(
    out: str | Path,
    n_entities: int = 25,
    alerts_per_entity: int = 400,
    seed: int = 42,
    anomaly_rate: float = .15,
    batch_size: int = 50_000,
    on_progress: Callable[[int], int | None] | None = None,
) -> dict[str, int]:
    """Stream a synthetic submission to CSV/parquet in bounded alert batches.

    Unlike :func:`generate`, this is the CLI/large-scale path: it never retains
    prior alert batches in RAM.  Only entity/asset metadata and ground truth
    (both proportional to CSE count) remain resident.
    """
    if n_entities < 4:
        raise ValueError("At least 4 entities are required to form meaningful peer cohorts")
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    destination = Path(out); destination.mkdir(parents=True, exist_ok=True)
    # A run owns these generated artifacts; replace a previous run atomically by
    # file, rather than accidentally appending old CSV batches to a new parquet.
    for name in ("entities", "assets", "alerts", "cases", "escalations", "ground_truth"):
        for suffix in (".csv", ".parquet"):
            target = destination / f"{name}{suffix}"
            if target.exists():
                target.unlink()
    rng = np.random.default_rng(seed)
    reference = datetime(2026, 8, 30, 12, tzinfo=timezone.utc)
    anomaly_count = max(1, round(n_entities * anomaly_rate))
    pools = {detector: set(rng.choice(np.arange(n_entities), size=anomaly_count, replace=False)) for detector in ("fast_closure", "no_escalation", "low_coverage")}
    entities: list[dict] = []
    assets: list[dict] = []
    cases: list[dict] = []
    truth: list[dict] = []
    alert_writer = _BatchWriter(destination, "alerts")
    alert_number = 0
    current_batch_size = batch_size
    written = 0
    try:
        for entity_idx in range(n_entities):
            entity_id = f"CSE-{entity_idx + 1:03d}"
            case_id = f"CASE-{entity_idx + 1:03d}"
            entities.append({"entity_id": entity_id, "name": f"Synthetic CSE {entity_idx + 1}", "peer_group": "finserv-tier2" if entity_idx % 2 == 0 else "energy-tier2", "sector": "financial" if entity_idx % 2 == 0 else "energy"})
            own_assets = []
            for asset_idx in range(3):
                asset = {"asset_id": f"AST-{entity_idx+1:03d}-{asset_idx+1}", "entity_id": entity_id, "criticality": "critical" if asset_idx < 2 else "high", "asset_type": "payment gateway" if asset_idx == 0 else "domain controller"}
                assets.append(asset); own_assets.append(asset)
            low_asset = own_assets[0]["asset_id"]
            candidates = [asset["asset_id"] for asset in own_assets if not (entity_idx in pools["low_coverage"] and asset["asset_id"] == low_asset)]
            remaining = alerts_per_entity
            first_alert = None
            while remaining:
                size = min(current_batch_size, remaining)
                rows = []
                for _ in range(size):
                    alert_number += 1
                    created = reference - timedelta(minutes=int(rng.integers(0, 29 * 24 * 60)))
                    severity = rng.choice(["low", "medium", "high", "critical"], p=[.35, .35, .22, .08]).item()
                    duration = int(np.clip(rng.normal(480, 35), 420, 600)) if severity in {"high", "critical"} else int(rng.integers(60, 600))
                    disposition = rng.choice(["true_positive", "false_positive", "benign", "unresolved"], p=[.22, .35, .35, .08]).item()
                    escalated = bool(severity == "critical" and disposition == "true_positive")
                    alert = {"alert_id": f"AL-{alert_number:09d}", "entity_id": entity_id, "asset_id": rng.choice(candidates).item(), "category": rng.choice(["malware", "intrusion", "phishing", "DoS"]).item(), "severity": severity, "created_at": created.isoformat(), "first_ack_at": (created + timedelta(minutes=5)).isoformat(), "closed_at": (created + timedelta(minutes=duration)).isoformat(), "disposition": disposition, "escalated": escalated, "escalated_at": (created + timedelta(minutes=30)).isoformat() if escalated else None, "case_id": None}
                    if first_alert is None:
                        first_alert = alert
                        alert["case_id"] = case_id
                        _truth_for_alert(truth, alert, disposition == "true_positive")
                    else:
                        _truth_for_alert(truth, alert)
                    rows.append(alert)
                alert_writer.write(pd.DataFrame(rows))
                remaining -= size; written += size
                if on_progress:
                    suggested_size = on_progress(size)
                    if suggested_size:
                        current_batch_size = max(1, int(suggested_size))
            injected = []
            if entity_idx in pools["fast_closure"]:
                alert_number += 1; created = reference - timedelta(hours=1); alert_id = f"AL-{alert_number:09d}"
                injected.append({"alert_id": alert_id, "entity_id": entity_id, "asset_id": own_assets[1]["asset_id"], "category": "intrusion", "severity": "high", "created_at": created.isoformat(), "first_ack_at": created.isoformat(), "closed_at": (created + timedelta(minutes=2)).isoformat(), "disposition": "true_positive", "escalated": True, "escalated_at": (created + timedelta(minutes=1)).isoformat(), "case_id": None})
                _truth_for_alert(truth, injected[-1])
                truth.append({"detector": "fast_closure", "entity_id": entity_id, "alert_id": alert_id, "asset_id": None})
            if entity_idx in pools["no_escalation"]:
                alert_number += 1; created = reference - timedelta(hours=10); alert_id = f"AL-{alert_number:09d}"
                injected.append({"alert_id": alert_id, "entity_id": entity_id, "asset_id": own_assets[1]["asset_id"], "category": "malware", "severity": "critical", "created_at": created.isoformat(), "first_ack_at": created.isoformat(), "closed_at": (created + timedelta(hours=8)).isoformat(), "disposition": "true_positive", "escalated": False, "escalated_at": None, "case_id": None})
                _truth_for_alert(truth, injected[-1])
                truth.append({"detector": "no_escalation", "entity_id": entity_id, "alert_id": alert_id, "asset_id": None})
            if injected:
                alert_writer.write(pd.DataFrame(injected)); written += len(injected)
                if on_progress:
                    suggested_size = on_progress(len(injected))
                    if suggested_size:
                        current_batch_size = max(1, int(suggested_size))
            if entity_idx in pools["low_coverage"]:
                truth.append({"detector": "low_coverage", "entity_id": entity_id, "alert_id": None, "asset_id": low_asset})
            cases.append({"case_id": case_id, "entity_id": entity_id,
                          "opened_at": first_alert["created_at"],
                          "closed_at": first_alert["closed_at"],
                          "alert_ids": [first_alert["alert_id"]],
                          "root_cause_documented": first_alert["disposition"] == "true_positive"})
    finally:
        alert_writer.close()
    frames = {
        "entities": pd.DataFrame(entities), "assets": pd.DataFrame(assets),
        "cases": pd.DataFrame(cases, columns=["case_id", "entity_id", "opened_at", "closed_at", "alert_ids", "root_cause_documented"]),
        "escalations": pd.DataFrame(columns=["escalation_id", "alert_id", "escalated_at", "escalated_to_tier"]),
        "ground_truth": pd.DataFrame(truth),
    }
    for name, frame in frames.items():
        csv_frame = frame.copy()
        if name == "cases" and not csv_frame.empty:
            csv_frame["alert_ids"] = csv_frame["alert_ids"].map(json.dumps)
        csv_frame.to_csv(destination / f"{name}.csv", index=False)
        frame.to_parquet(destination / f"{name}.parquet", index=False)
    return {"alerts": written, "entities": n_entities}
