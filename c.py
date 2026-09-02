"""
SAT-SA Supervisor Workbench
============================

A Streamlit presentation layer for the SAT-SA CLI (`sat_sa.cli` / the `satsa`
console script). This app does not reimplement any detector, scoring, or
benchmarking logic — it drives the real pipeline as a subprocess
(`python -m sat_sa.cli ...`) exactly as the CLI is documented, and then reads
the ordinary local artifacts that pipeline writes (flags.json,
entity_scores.csv, alert_volumes.json, rejects.json, report.json, and the
normalized parquet tables). A handful of small, clearly-marked JSON files
(disposition log, review queue, per-run detector config) are owned by this
UI layer only, so an examiner's review notes survive between sessions.

Run it with:

    streamlit run app.py

It expects to be launched from an environment where `python -m sat_sa.cli`
works (i.e. the `sat_sa` package is installed). Every assessment run writes
under ./runs/<run-name>/{source,normalized,results}, matching the layout the
CLI docs describe, so multiple periodic submissions can sit side by side.

Optional extra dependency: `plotly` (for the peer-benchmarking box plot). If
it isn't installed the page falls back to a native chart automatically.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st
import yaml

try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


# ────────────────────────────────────────────────────────────────────────
# Paths & constants
# ────────────────────────────────────────────────────────────────────────

APP_ROOT = Path(__file__).resolve().parent
RUNS_DIR = APP_ROOT / "runs"
RUNS_DIR.mkdir(exist_ok=True)

REQUIRED_TABLES = ["entities", "assets", "alerts", "cases", "escalations"]
UPLOAD_LABELS = ["entities.csv", "assets.csv", "alerts.csv", "cases.csv", "escalations.csv"]

DEFAULT_WEIGHTS = {"fast_closure": 2.0, "no_escalation": 3.0, "low_coverage": 2.0}
DEFAULT_THRESHOLDS = {"fast_closure_k": 1.5, "coverage_window_days": 30, "coverage_threshold_pct": 0.25}

DETECTOR_INFO = {
    "fast_closure": {
        "label": "Fast closure",
        "family": "EG",
        "group": "execution_gaps",
        "question": "Are high-impact alerts being closed without meaningful investigation?",
        "method": "Severity-specific Q1 \u2212 1.5\u00d7IQR lower fence (Tukey's fence) on time-to-close, high/critical severities only.",
        "evidence_hint": "alert_ids, observed_value, baseline_value (Q1), time_to_close_minutes, baseline_q1_minutes, baseline_iqr_minutes",
    },
    "no_escalation": {
        "label": "No escalation",
        "family": "EG",
        "group": "execution_gaps",
        "question": "Was a critical true-positive closed without recorded escalation?",
        "method": "Deterministic rule: severity = critical AND disposition = true_positive AND escalated = false. No statistical baseline.",
        "evidence_hint": "alert_ids, disposition, closed_at, escalated",
    },
    "low_coverage": {
        "label": "Low coverage",
        "family": "NS",
        "group": "negative_space",
        "question": "Does a critical asset show a possible monitoring blind spot?",
        "method": "30-day observed alert count on a critical asset < 25% of its peer critical-asset median.",
        "evidence_hint": "asset_id, window_days, observed count, peer median, peer group",
    },
}

FAMILY_LABELS = {"EG": "Execution gap", "NS": "Negative space"}

# Status semantics used throughout (spec \u00a72): red = critical/unresolved,
# amber = medium/needs attention, green = low risk/cleared, gray = neutral/no data.
STATUS_BADGE_COLOR = {"red": "red", "amber": "orange", "green": "green", "gray": "gray"}
STATUS_DOT = {"red": "\U0001F534", "amber": "\U0001F7E1", "green": "\U0001F7E2", "gray": "\u26AA"}

DISPOSITION_BADGE = {
    "reviewed_benign": ("Reviewed \u2013 benign", "green"),
    "confirmed_escalate": ("Confirmed \u2013 escalate", "red"),
    "insufficient_evidence": ("Insufficient evidence", "orange"),
}

PRESETS = {
    "Default \u2014 small demonstration": {"entities": 8, "alerts": 8_000, "anomaly_rate": 0.25, "use": "live presentation"},
    "Medium \u2014 departmental assessment": {"entities": 20, "alerts": 200_000, "anomaly_rate": 0.15, "use": "multi-CSE assessment"},
    "Large \u2014 supervisory batch": {"entities": 40, "alerts": 2_000_000, "anomaly_rate": 0.15, "use": "scalability demonstration"},
    "Gigantic \u2014 national-scale rehearsal": {"entities": 100, "alerts": 10_000_000, "anomaly_rate": 0.10, "use": "capacity rehearsal"},
}

MAX_TREND_RUNS = 4


# ────────────────────────────────────────────────────────────────────────
# Run directory model
# ────────────────────────────────────────────────────────────────────────
#
# Each assessment cycle is a "run": runs/<name>/{source,normalized,results}.
# The CLI itself has no notion of a "cycle" across time (01-product doc \u00a76
# is explicit that only the current submission is in scope) — the run
# directory is this UI's honest stand-in for the supervisor spec's "cycle":
# every page below that talks about comparing to a prior cycle is really
# comparing to a prior *local run*.


def sanitize_run_name(name: str) -> str:
    """64-char A-Za-z0-9_- names only, per the workbench safety constraints."""
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "-", (name or "").strip())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-_")
    if not cleaned:
        cleaned = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    return cleaned[:64]


def default_run_name() -> str:
    return f"assessment-{datetime.now().strftime('%Y%m%d-%H%M')}"


@dataclass(frozen=True)
class RunPaths:
    name: str
    root: Path
    source: Path
    normalized: Path
    results: Path

    @property
    def flags_json(self) -> Path:
        return self.results / "flags.json"

    @property
    def alert_volumes_json(self) -> Path:
        return self.results / "alert_volumes.json"

    @property
    def entity_scores_csv(self) -> Path:
        return self.results / "entity_scores.csv"

    @property
    def report_json(self) -> Path:
        return self.results / "report.json"

    @property
    def rejects_json(self) -> Path:
        return self.normalized / "rejects.json"

    @property
    def validation_txt(self) -> Path:
        return self.results / "validation_output.txt"

    @property
    def detector_config_yaml(self) -> Path:
        return self.results / "detector_config.yaml"

    @property
    def ground_truth_parquet(self) -> Path:
        return self.source / "ground_truth.parquet"

    # UI-layer-only artifacts (not part of the sat_sa data contract):
    @property
    def dispositions_json(self) -> Path:
        return self.results / "_ui_dispositions.json"

    @property
    def review_queue_json(self) -> Path:
        return self.results / "_ui_review_queue.json"


def run_paths(name: str) -> RunPaths:
    root = RUNS_DIR / name
    return RunPaths(name=name, root=root, source=root / "source",
                     normalized=root / "normalized", results=root / "results")


def list_runs() -> list[str]:
    """Most-recently-active run first."""
    if not RUNS_DIR.exists():
        return []

    def sort_key(p: Path) -> float:
        rp = run_paths(p.name)
        for candidate in (rp.entity_scores_csv, rp.flags_json, rp.root):
            if candidate.exists():
                try:
                    return candidate.stat().st_mtime
                except OSError:
                    continue
        return 0.0

    dirs = [p for p in RUNS_DIR.iterdir() if p.is_dir()]
    dirs.sort(key=sort_key, reverse=True)
    return [p.name for p in dirs]


def run_status(name: str) -> str:
    """One of empty / sourced / ingested / detected / scored."""
    rp = run_paths(name)
    if rp.entity_scores_csv.exists() and rp.report_json.exists():
        return "scored"
    if rp.flags_json.exists():
        return "detected"
    if rp.normalized.exists() and any(rp.normalized.glob("*.parquet")):
        return "ingested"
    if rp.source.exists() and any(rp.source.iterdir()) if rp.source.exists() else False:
        return "sourced"
    return "empty"


def get_previous_run(active: str) -> Optional[str]:
    runs = list_runs()
    if active not in runs:
        return None
    idx = runs.index(active)
    return runs[idx + 1] if idx + 1 < len(runs) else None


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return -1.0


# ────────────────────────────────────────────────────────────────────────
# CLI subprocess bridge — the only way this app talks to SAT-SA's analytics
# ────────────────────────────────────────────────────────────────────────


def cli_base_args() -> list[str]:
    return [sys.executable, "-m", "sat_sa.cli"]


def run_cli(args: list[str], timeout: Optional[int] = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cli_base_args() + args, capture_output=True, text=True, timeout=timeout)


@st.cache_data(show_spinner=False, ttl=30)
def cli_status() -> tuple[bool, str]:
    try:
        result = run_cli(["--help"], timeout=15)
        return result.returncode == 0, (result.stdout or result.stderr or "")
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


@st.cache_data(show_spinner=False, ttl=60)
def get_system_info() -> Optional[dict]:
    try:
        result = run_cli(["system-info"], timeout=20)
    except Exception:
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def run_cli_streaming(args: list[str], log_area) -> tuple[int, str]:
    """Run a CLI subcommand, streaming stdout/stderr into a Streamlit
    placeholder as it arrives. Returns (returncode, full captured text)."""
    try:
        proc = subprocess.Popen(
            cli_base_args() + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        log_area.code(f"Could not launch the Python interpreter: {exc}", language="text")
        return 1, str(exc)

    lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        lines.append(line.rstrip("\n"))
        log_area.code("\n".join(lines[-60:]) or "(no output yet)", language="text")
    proc.wait()
    full = "\n".join(lines)
    if not lines:
        log_area.code("(command produced no output)", language="text")
    return proc.returncode, full


def write_detector_config(rp: RunPaths, thresholds: dict, weights: dict) -> Path:
    rp.results.mkdir(parents=True, exist_ok=True)
    config = {
        "fast_closure_k": thresholds["fast_closure_k"],
        "coverage_window_days": int(thresholds["coverage_window_days"]),
        "coverage_threshold_pct": thresholds["coverage_threshold_pct"],
        "weights": {
            "fast_closure": weights["fast_closure"],
            "no_escalation": weights["no_escalation"],
            "low_coverage": weights["low_coverage"],
        },
    }
    with open(rp.detector_config_yaml, "w", encoding="utf-8") as fh:
        yaml.safe_dump(config, fh, sort_keys=False)
    return rp.detector_config_yaml


def load_run_config(rp: RunPaths) -> tuple[dict, dict]:
    """Returns (thresholds, weights) for a run, falling back to CLI defaults
    (architecture.md / 04-analytics-and-evidence.md) if no config was saved."""
    if rp.detector_config_yaml.exists():
        try:
            with open(rp.detector_config_yaml, "r", encoding="utf-8") as fh:
                cfg = yaml.safe_load(fh) or {}
            thresholds = {
                "fast_closure_k": cfg.get("fast_closure_k", DEFAULT_THRESHOLDS["fast_closure_k"]),
                "coverage_window_days": cfg.get("coverage_window_days", DEFAULT_THRESHOLDS["coverage_window_days"]),
                "coverage_threshold_pct": cfg.get("coverage_threshold_pct", DEFAULT_THRESHOLDS["coverage_threshold_pct"]),
            }
            weights = {**DEFAULT_WEIGHTS, **(cfg.get("weights") or {})}
            return thresholds, weights
        except Exception:
            pass
    return dict(DEFAULT_THRESHOLDS), dict(DEFAULT_WEIGHTS)


# ────────────────────────────────────────────────────────────────────────
# Cached readers for the CLI's own output artifacts
# ────────────────────────────────────────────────────────────────────────


@st.cache_data(show_spinner=False)
def _read_parquet_tables(normalized_dir: str, mtimes: tuple) -> dict[str, pd.DataFrame]:
    base = Path(normalized_dir)
    tables: dict[str, pd.DataFrame] = {}
    for name in REQUIRED_TABLES:
        path = base / f"{name}.parquet"
        if path.exists():
            try:
                tables[name] = pd.read_parquet(path)
            except Exception:
                tables[name] = pd.DataFrame()
        else:
            tables[name] = pd.DataFrame()
    return tables


def get_normalized_tables(rp: RunPaths) -> dict[str, pd.DataFrame]:
    mtimes = tuple(_mtime(rp.normalized / f"{n}.parquet") for n in REQUIRED_TABLES)
    return _read_parquet_tables(str(rp.normalized), mtimes)


def flag_reference_id(detector: str, evidence: dict) -> str:
    """Best-effort extraction of the record ID a flag is about, tolerant of
    either an *_ids list or a singular *_id key (04-analytics-and-evidence.md
    documents the list form for D1/D2 evidence; D3 evidence names an asset)."""
    evidence = evidence or {}
    for key in ("alert_ids", "asset_ids"):
        val = evidence.get(key)
        if isinstance(val, list) and val:
            return str(val[0])
    for key in ("alert_id", "asset_id"):
        if evidence.get(key):
            return str(evidence[key])
    return ""


@st.cache_data(show_spinner=False)
def _read_flags(flags_path: str, mtime: float) -> pd.DataFrame:
    path = Path(flags_path)
    columns = ["flag_id", "detector", "family", "entity_id", "severity_weight",
               "rationale", "evidence", "generated_at", "reference_id"]
    if not path.exists():
        return pd.DataFrame(columns=columns)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return pd.DataFrame(columns=columns)
    if not raw:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(raw)
    for col in ("flag_id", "detector", "entity_id", "rationale"):
        if col not in df.columns:
            df[col] = ""
    if "severity_weight" not in df.columns:
        df["severity_weight"] = 0.0
    if "evidence" not in df.columns:
        df["evidence"] = [dict() for _ in range(len(df))]
    df["evidence"] = df["evidence"].apply(lambda e: e if isinstance(e, dict) else {})
    df["family"] = df["detector"].map(lambda d: DETECTOR_INFO.get(d, {}).get("family", "?"))
    df["reference_id"] = df.apply(lambda r: flag_reference_id(r["detector"], r["evidence"]), axis=1)
    if "generated_at" in df.columns:
        df["generated_at"] = pd.to_datetime(df["generated_at"], utc=True, errors="coerce")
    else:
        df["generated_at"] = pd.NaT
    return df


def get_flags_df(rp: RunPaths) -> pd.DataFrame:
    return _read_flags(str(rp.flags_json), _mtime(rp.flags_json))


@st.cache_data(show_spinner=False)
def _read_alert_volumes(path_str: str, mtime: float) -> dict:
    path = Path(path_str)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def get_alert_volumes(rp: RunPaths) -> dict:
    return _read_alert_volumes(str(rp.alert_volumes_json), _mtime(rp.alert_volumes_json))


@st.cache_data(show_spinner=False)
def _read_entity_scores(path_str: str, mtime: float) -> pd.DataFrame:
    path = Path(path_str)
    columns = ["entity_id", "risk_score", "priority_rank", "flag_count_by_detector",
               "distinct_detectors_triggered", "alert_volume", "flag_counts"]
    if not path.exists():
        return pd.DataFrame(columns=columns)
    try:
        df = pd.read_csv(path)
    except Exception:
        return pd.DataFrame(columns=columns)

    def parse_counts(val: Any) -> dict:
        if isinstance(val, dict):
            return val
        try:
            return json.loads(val)
        except Exception:
            return {}

    if "flag_count_by_detector" in df.columns:
        df["flag_counts"] = df["flag_count_by_detector"].apply(parse_counts)
    else:
        df["flag_counts"] = [dict() for _ in range(len(df))]
    return df


def get_entity_scores(rp: RunPaths) -> pd.DataFrame:
    return _read_entity_scores(str(rp.entity_scores_csv), _mtime(rp.entity_scores_csv))


@st.cache_data(show_spinner=False)
def _read_rejects(path_str: str, mtime: float) -> pd.DataFrame:
    path = Path(path_str)
    columns = ["source", "table", "row", "reason", "record"]
    if not path.exists():
        return pd.DataFrame(columns=columns)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return pd.DataFrame(columns=columns)
    if not raw:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(raw)


def get_rejects_df(rp: RunPaths) -> pd.DataFrame:
    return _read_rejects(str(rp.rejects_json), _mtime(rp.rejects_json))


@st.cache_data(show_spinner=False)
def _read_report(path_str: str, mtime: float) -> Optional[dict]:
    path = Path(path_str)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def get_report(rp: RunPaths) -> Optional[dict]:
    return _read_report(str(rp.report_json), _mtime(rp.report_json))


def get_validation_text(rp: RunPaths) -> Optional[str]:
    if rp.validation_txt.exists():
        try:
            return rp.validation_txt.read_text(encoding="utf-8")
        except Exception:
            return None
    return None


# ────────────────────────────────────────────────────────────────────────
# UI-layer persistence: disposition log + review queue
# ────────────────────────────────────────────────────────────────────────
# These two JSON files are NOT part of the sat_sa data contract — they are
# owned entirely by this dashboard so an examiner's review work survives
# between sessions. The disposition log is append-only by design (it is the
# audit trail the spec calls for); the review queue is a small mutable list.


def load_json_list(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_json_list(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    tmp.replace(path)


def append_disposition(rp: RunPaths, finding_id: str, entity_id: str, decision: str,
                        note: str, examiner: str) -> None:
    entries = load_json_list(rp.dispositions_json)
    entries.append({
        "finding_id": finding_id,
        "entity_id": entity_id,
        "decision": decision,
        "note": note,
        "examiner": examiner or "unattributed",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    })
    save_json_list(rp.dispositions_json, entries)


def all_dispositions(rp: RunPaths) -> pd.DataFrame:
    entries = load_json_list(rp.dispositions_json)
    if not entries:
        return pd.DataFrame(columns=["finding_id", "entity_id", "decision", "note", "examiner", "recorded_at"])
    return pd.DataFrame(entries)


def latest_disposition(rp: RunPaths, finding_id: str) -> Optional[dict]:
    entries = [e for e in load_json_list(rp.dispositions_json) if e.get("finding_id") == finding_id]
    return entries[-1] if entries else None


def latest_disposition_map(rp: RunPaths) -> dict[str, dict]:
    entries = load_json_list(rp.dispositions_json)
    latest: dict[str, dict] = {}
    for entry in entries:
        latest[entry.get("finding_id")] = entry
    return latest


def review_queue_items(rp: RunPaths) -> list[dict]:
    return load_json_list(rp.review_queue_json)


def add_to_review_queue(rp: RunPaths, reference_type: str, reference_id: str, entity_id: str,
                         reason: str, priority_score: float) -> bool:
    items = review_queue_items(rp)
    if any(i.get("reference_id") == reference_id for i in items):
        return False
    items.append({
        "reference_type": reference_type,
        "reference_id": reference_id,
        "entity_id": entity_id,
        "reason": reason,
        "priority_score": priority_score,
        "status": "To review",
        "assignee": "",
        "added_at": datetime.now(timezone.utc).isoformat(),
    })
    save_json_list(rp.review_queue_json, items)
    return True


def save_review_queue(rp: RunPaths, items: list[dict]) -> None:
    save_json_list(rp.review_queue_json, items)


# ────────────────────────────────────────────────────────────────────────
# Analytics helpers computed here for display only (peer benchmarking,
# score decomposition, coverage). These mirror the documented contracts of
# sat_sa.peer.benchmark and the scoring formula in
# 04-analytics-and-evidence.md \u00a76/\u00a78 — they do not decide any flag; the
# flags themselves always come straight from flags.json.
# ────────────────────────────────────────────────────────────────────────


def peer_benchmark(df: pd.DataFrame, group_col: str, metric_col: str, peer_group_col: str) -> pd.DataFrame:
    cols = [group_col, peer_group_col, metric_col, "peer_median", "q1", "q3", "iqr", "percentile_rank"]
    d = df[[group_col, metric_col, peer_group_col]].dropna()
    if d.empty:
        return pd.DataFrame(columns=cols)
    d = d.groupby([group_col, peer_group_col], as_index=False)[metric_col].median()
    out_rows = []
    for peer_group, sub in d.groupby(peer_group_col):
        median = sub[metric_col].median()
        q1 = sub[metric_col].quantile(0.25)
        q3 = sub[metric_col].quantile(0.75)
        iqr = q3 - q1
        ranks = sub[metric_col].rank(pct=True, method="average")
        for (_, row), pct in zip(sub.iterrows(), ranks):
            out_rows.append({
                group_col: row[group_col],
                peer_group_col: peer_group,
                metric_col: row[metric_col],
                "peer_median": median,
                "q1": q1,
                "q3": q3,
                "iqr": iqr,
                "percentile_rank": pct,
            })
    return pd.DataFrame(out_rows)


def decompose_score(flag_counts: dict, alert_volume: float, weights: dict) -> dict:
    """Splits the documented risk formula
    risk = sum(weight * count) / log(1 + volume) into its EG and NS parts.
    EG_component + NS_component reproduces risk_score exactly."""
    flag_counts = flag_counts or {}
    eg_raw = (weights.get("fast_closure", 2) * flag_counts.get("fast_closure", 0)
              + weights.get("no_escalation", 3) * flag_counts.get("no_escalation", 0))
    ns_raw = weights.get("low_coverage", 2) * flag_counts.get("low_coverage", 0)
    denom = math.log(1 + alert_volume) if alert_volume and alert_volume > 0 else 1.0
    return {"eg_component": eg_raw / denom, "ns_component": ns_raw / denom}


def compute_entity_metrics(tables: dict[str, pd.DataFrame], alert_volumes: dict) -> pd.DataFrame:
    """One row per entity: name, sector, peer_group, alert_volume,
    avg_case_closure_hours, escalation_rate, critical_asset_count, asset_count."""
    entities = tables.get("entities", pd.DataFrame())
    if entities.empty:
        return pd.DataFrame()

    base = entities.copy()
    if "sector" not in base.columns:
        base["sector"] = None
    base = base[["entity_id", "name", "peer_group", "sector"]]

    alerts = tables.get("alerts", pd.DataFrame())
    if not alerts.empty:
        counts = alerts.groupby("entity_id").size()
        base["alert_volume"] = base["entity_id"].apply(
            lambda e: alert_volumes.get(e, int(counts.get(e, 0))))
        if "escalated" in alerts.columns:
            esc_rate = alerts.groupby("entity_id")["escalated"].mean()
            base["escalation_rate"] = base["entity_id"].map(esc_rate).fillna(0.0)
        else:
            base["escalation_rate"] = 0.0
    else:
        base["alert_volume"] = base["entity_id"].apply(lambda e: alert_volumes.get(e, 0))
        base["escalation_rate"] = 0.0

    cases = tables.get("cases", pd.DataFrame())
    if not cases.empty and "closed_at" in cases.columns and "opened_at" in cases.columns:
        c = cases.dropna(subset=["closed_at"]).copy()
        c["opened_at"] = pd.to_datetime(c["opened_at"], utc=True, errors="coerce")
        c["closed_at"] = pd.to_datetime(c["closed_at"], utc=True, errors="coerce")
        c["closure_hours"] = (c["closed_at"] - c["opened_at"]).dt.total_seconds() / 3600.0
        avg_closure = c.groupby("entity_id")["closure_hours"].mean()
        base["avg_case_closure_hours"] = base["entity_id"].map(avg_closure)
    else:
        base["avg_case_closure_hours"] = pd.NA

    assets = tables.get("assets", pd.DataFrame())
    if not assets.empty:
        crit_counts = assets[assets.get("criticality") == "critical"].groupby("entity_id").size()
        all_counts = assets.groupby("entity_id").size()
        base["critical_asset_count"] = base["entity_id"].map(crit_counts).fillna(0).astype(int)
        base["asset_count"] = base["entity_id"].map(all_counts).fillna(0).astype(int)
    else:
        base["critical_asset_count"] = 0
        base["asset_count"] = 0

    return base


def compute_peer_deviation(tables: dict[str, pd.DataFrame], alert_volumes: dict) -> pd.DataFrame:
    """0 (at peer median) to 1 (most extreme peer) deviation score, based on
    alert-volume percentile rank within sector/peer group."""
    entities = tables.get("entities", pd.DataFrame())
    if entities.empty:
        return pd.DataFrame(columns=["entity_id", "peer_deviation_pct"])
    df = entities[["entity_id", "peer_group"]].copy()
    df["alert_volume"] = df["entity_id"].apply(lambda e: alert_volumes.get(e, 0))
    bench = peer_benchmark(df, "entity_id", "alert_volume", "peer_group")
    if bench.empty:
        df["peer_deviation_pct"] = 0.0
        return df[["entity_id", "peer_deviation_pct"]]
    bench["peer_deviation_pct"] = (bench["percentile_rank"] - 0.5).abs() * 2
    return bench[["entity_id", "peer_deviation_pct"]]


def compute_asset_coverage(tables: dict[str, pd.DataFrame], window_days: int, threshold_pct: float) -> pd.DataFrame:
    """Descriptive TelemetryStatus per critical asset (red/amber/green/gray),
    reproducing D3's method for visualization. flags.json remains the source
    of truth for which assets were actually flagged."""
    assets = tables.get("assets", pd.DataFrame())
    alerts = tables.get("alerts", pd.DataFrame())
    entities = tables.get("entities", pd.DataFrame())
    if assets.empty or "criticality" not in assets.columns:
        return pd.DataFrame()

    crit = assets[assets["criticality"] == "critical"].copy()
    if crit.empty:
        return crit

    if not entities.empty and "peer_group" in entities.columns:
        crit = crit.merge(entities[["entity_id", "peer_group"]], on="entity_id", how="left")
    else:
        crit["peer_group"] = None

    if alerts.empty or "created_at" not in alerts.columns:
        crit["observed_count"] = 0
        crit["peer_median"] = pd.NA
        crit["status"] = "gray"
        return crit

    a = alerts.copy()
    a["created_at"] = pd.to_datetime(a["created_at"], utc=True, errors="coerce")
    reference = a["created_at"].max()
    if pd.isna(reference):
        crit["observed_count"] = 0
        crit["peer_median"] = pd.NA
        crit["status"] = "gray"
        return crit

    window_start = reference - pd.Timedelta(days=window_days)
    recent = a[(a["created_at"] >= window_start) & (a["created_at"] <= reference)]
    counts = recent.groupby("asset_id").size() if "asset_id" in recent.columns else pd.Series(dtype=int)
    crit["observed_count"] = crit["asset_id"].map(counts).fillna(0).astype(int)

    bench = peer_benchmark(crit, group_col="asset_id", metric_col="observed_count", peer_group_col="peer_group")
    if not bench.empty:
        crit = crit.merge(bench[["asset_id", "peer_median"]], on="asset_id", how="left")
    else:
        crit["peer_median"] = pd.NA

    def status_for(row) -> str:
        median = row.get("peer_median")
        if pd.isna(median) or median == 0:
            return "gray"
        if row["observed_count"] < threshold_pct * median:
            return "red"
        if row["observed_count"] < median:
            return "amber"
        return "green"

    crit["status"] = crit.apply(status_for, axis=1)
    return crit


def flag_recurrence_key(row: pd.Series) -> tuple:
    return (row.get("entity_id"), row.get("detector"), row.get("reference_id"))


def compute_recurrence_keys(previous_flags: pd.DataFrame) -> set[tuple]:
    if previous_flags is None or previous_flags.empty:
        return set()
    return {flag_recurrence_key(r) for _, r in previous_flags.iterrows()}


def entity_score_history(entity_id: str, max_runs: int = MAX_TREND_RUNS) -> pd.DataFrame:
    runs = list(reversed(list_runs()[:max_runs]))  # oldest -> newest
    records = []
    for r in runs:
        rp = run_paths(r)
        df = get_entity_scores(rp)
        if df.empty:
            continue
        match = df[df["entity_id"] == entity_id]
        if not match.empty:
            records.append({"run": r, "risk_score": float(match.iloc[0]["risk_score"])})
    return pd.DataFrame(records)


def portfolio_trend_map(entity_ids: list[str], max_runs: int = MAX_TREND_RUNS) -> dict[str, list[float]]:
    runs = list(reversed(list_runs()[:max_runs]))  # oldest -> newest
    trend: dict[str, list[float]] = {eid: [] for eid in entity_ids}
    for r in runs:
        df = get_entity_scores(run_paths(r))
        if df.empty:
            continue
        score_map = dict(zip(df["entity_id"], df["risk_score"]))
        for eid in entity_ids:
            if eid in score_map:
                trend[eid].append(round(float(score_map[eid]), 4))
    return trend


# ────────────────────────────────────────────────────────────────────────
# Small formatting helpers
# ────────────────────────────────────────────────────────────────────────


def fmt_minutes(minutes: Optional[float]) -> str:
    """Integer minutes below 60, otherwise one-decimal hours — matches the
    CLI's own duration formatting (07-module-implementation-blueprint.md)."""
    if minutes is None or (isinstance(minutes, float) and math.isnan(minutes)):
        return "\u2013"
    if minutes < 60:
        return f"{int(round(minutes))}m"
    return f"{minutes / 60:.1f}h"


def fmt_hours(hours: Optional[float]) -> str:
    if hours is None or (isinstance(hours, float) and pd.isna(hours)):
        return "\u2013"
    if hours < 1:
        return f"{int(round(hours * 60))}m"
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d"


def fmt_pct(value: Optional[float]) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "\u2013"
    return f"{value * 100:.0f}%"


def family_badge(detector: str) -> None:
    family = DETECTOR_INFO.get(detector, {}).get("family", "?")
    color = "blue" if family == "EG" else "violet"
    st.badge(FAMILY_LABELS.get(family, family), color=color)


def disposition_badge(decision: Optional[str]) -> None:
    if not decision:
        st.badge("Pending review", color="gray")
        return
    label, color = DISPOSITION_BADGE.get(decision, (decision, "gray"))
    st.badge(label, color=color)


def status_row_text(status: str, label: str) -> str:
    return f"{STATUS_DOT.get(status, '\u26AA')} {label}"


def detector_short_label(detector: str) -> str:
    return DETECTOR_INFO.get(detector, {}).get("label", detector)


def risk_status_word(score: float, scale_max: float) -> str:
    if scale_max <= 0:
        return "gray"
    frac = score / scale_max
    if frac >= 0.66:
        return "red"
    if frac >= 0.33:
        return "amber"
    return "green"


# ────────────────────────────────────────────────────────────────────────
# Session-state / navigation plumbing
# ────────────────────────────────────────────────────────────────────────

DEFAULTS = {
    "active_run": None,
    "active_entity_id": None,
    "active_finding_id": None,
    "examiner_name": "",
}


def bootstrap_session_state() -> None:
    for key, value in DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = value
    if st.session_state.active_run is None:
        runs = list_runs()
        if runs:
            st.session_state.active_run = runs[0]
    # Deep-link support: a shared URL can carry ?entity_id=... / ?finding_id=...
    qp_entity = st.query_params.get("entity_id")
    if qp_entity and not st.session_state.active_entity_id:
        st.session_state.active_entity_id = qp_entity
    qp_finding = st.query_params.get("finding_id")
    if qp_finding and not st.session_state.active_finding_id:
        st.session_state.active_finding_id = qp_finding


def set_active_entity(entity_id: str) -> None:
    st.session_state.active_entity_id = entity_id


PAGES: dict[str, Any] = {}  # populated once st.Page objects are created, at the bottom of this file


def goto(page_key: str, **query_params) -> None:
    target = PAGES.get(page_key)
    if target is None:
        return
    st.switch_page(target, query_params=query_params or None)


def empty_state_no_run() -> None:
    st.info("No assessment runs yet. Start one on **Run assessment** to generate or ingest a submission.")
    if st.button("Go to Run assessment \u2192", type="primary"):
        goto("run_assessment")


# ────────────────────────────────────────────────────────────────────────
# Global sidebar — present on every page (this is the "picture frame" that
# st.navigation's entrypoint file provides around each page).
# ────────────────────────────────────────────────────────────────────────

STATUS_LABELS = {
    "empty": ("No data yet", "gray"),
    "sourced": ("Data staged", "gray"),
    "ingested": ("Ingested, not yet detected", "amber"),
    "detected": ("Detected, not yet scored", "amber"),
    "scored": ("Ready", "green"),
}


def render_sidebar() -> None:
    with st.sidebar:
        st.markdown("### \U0001F6E1\uFE0F SAT-SA")
        st.caption("Supervisory Analytics for SOC Assessment \u2014 examiner workbench")

        runs = list_runs()
        if runs:
            current = st.session_state.active_run if st.session_state.active_run in runs else runs[0]
            chosen = st.selectbox(
                "Assessment run (cycle)", runs, index=runs.index(current),
                help="Each run is one periodic submission cycle: runs/<name>/",
            )
            if chosen != st.session_state.active_run:
                st.session_state.active_run = chosen
                st.session_state.active_entity_id = None
                st.session_state.active_finding_id = None
                st.rerun()

            status, color = STATUS_LABELS.get(run_status(chosen), ("Unknown", "gray"))
            st.badge(status, color=STATUS_BADGE_COLOR.get(color, "gray"))
        else:
            st.info("No runs yet.")

        if st.button("\U0001F504 Refresh data", width="stretch"):
            st.cache_data.clear()
            st.rerun()

        st.divider()

        search = st.text_input("Search entity or finding ID", placeholder="e.g. CSE-001 or fg_00007")
        if search:
            active = st.session_state.get("active_run")
            if active:
                rp = run_paths(active)
                tables = get_normalized_tables(rp)
                entities = tables.get("entities", pd.DataFrame())
                needle = search.strip().lower()
                hit_entity = None
                if not entities.empty:
                    matches = entities[
                        entities["entity_id"].str.lower().str.contains(needle, na=False)
                        | entities["name"].str.lower().str.contains(needle, na=False)
                    ]
                    if not matches.empty:
                        hit_entity = matches.iloc[0]["entity_id"]
                flags_df = get_flags_df(rp)
                hit_finding = None
                if not flags_df.empty:
                    fmatches = flags_df[flags_df["flag_id"].str.lower() == needle]
                    if not fmatches.empty:
                        hit_finding = fmatches.iloc[0]["flag_id"]
                if hit_finding:
                    if st.button(f"Open finding {hit_finding} \u2192", key="search_open_finding"):
                        goto("findings_feed", finding_id=hit_finding)
                elif hit_entity:
                    if st.button(f"Open {hit_entity} \u2192", key="search_open_entity"):
                        set_active_entity(hit_entity)
                        goto("entity_profile", entity_id=hit_entity)
                else:
                    st.caption("No match in this run.")

        st.divider()
        st.session_state.examiner_name = st.text_input(
            "Examiner", value=st.session_state.examiner_name,
            placeholder="Your name", help="Attributed on any disposition you save.",
        )
        with st.expander("Host resources"):
            info = get_system_info()
            if info:
                st.json(info, expanded=False)
            else:
                st.caption("SAT-SA CLI not reachable \u2014 see Run assessment for details.")
        st.caption("SAT-SA MVP \u00b7 local, offline analytics \u2014 advisory only, not an enforcement outcome.")


# ────────────────────────────────────────────────────────────────────────
# Finding detail — a modal dialog reachable from any findings table, not a
# page of its own (Findings feed, Entity profile, Review queue all open it).
# ────────────────────────────────────────────────────────────────────────


@st.dialog("Finding detail", width="large")
def finding_detail_dialog(flag_id: str, rp: RunPaths) -> None:
    flags_df = get_flags_df(rp)
    match = flags_df[flags_df["flag_id"] == flag_id]
    if match.empty:
        st.error("This finding could not be found in the current run.")
        return
    row = match.iloc[0]
    evidence = row["evidence"] or {}
    existing = latest_disposition(rp, flag_id)

    head_l, head_r = st.columns([4, 1])
    with head_l:
        st.markdown(f"#### {row['rationale']}")
    with head_r:
        family_badge(row["detector"])
        disposition_badge(existing["decision"] if existing else None)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.caption("Entity")
        st.markdown(f"`{row['entity_id']}`")
    with c2:
        st.caption("Detector rule")
        st.markdown(detector_short_label(row["detector"]))
    with c3:
        st.caption("Detected")
        gen = row["generated_at"]
        st.markdown(gen.strftime("%Y-%m-%d %H:%M UTC") if pd.notna(gen) else "\u2013")

    with st.expander("Why this fired", expanded=True):
        info = DETECTOR_INFO.get(row["detector"], {})
        st.markdown(f"**Method:** {info.get('method', '\u2013')}")
        stat_cols = st.columns(3)
        detector = row["detector"]
        if detector == "fast_closure":
            stat_cols[0].metric("Observed closure time",
                                 evidence.get("observed_value") or fmt_minutes(evidence.get("time_to_close_minutes")))
            stat_cols[1].metric("Severity Q1 baseline",
                                 evidence.get("baseline_value") or fmt_minutes(evidence.get("baseline_q1_minutes")))
            stat_cols[2].metric("Severity IQR", fmt_minutes(evidence.get("baseline_iqr_minutes")))
            if evidence.get("baseline_source"):
                st.caption(f"Baseline: {evidence['baseline_source']}")
        elif detector == "no_escalation":
            stat_cols[0].metric("Disposition", str(evidence.get("disposition", "\u2013")))
            stat_cols[1].metric("Escalated", "No")
            stat_cols[2].metric("Closed at", str(evidence.get("closed_at", "\u2013"))[:19])
            st.caption("Deterministic rule \u2014 no statistical baseline is used for this detector.")
        elif detector == "low_coverage":
            stat_cols[0].metric("Observed alerts", evidence.get("observed_count", "\u2013"))
            stat_cols[1].metric("Peer median", evidence.get("peer_median", "\u2013"))
            threshold = evidence.get("threshold") or evidence.get("threshold_pct")
            stat_cols[2].metric("Threshold", fmt_pct(threshold) if threshold else "\u2013")
            extra = []
            if evidence.get("peer_group"):
                extra.append(f"peer group: {evidence['peer_group']}")
            if evidence.get("window_days"):
                extra.append(f"window: {evidence['window_days']} days")
            if extra:
                st.caption(" \u00b7 ".join(extra))
        else:
            st.caption("No structured statistic recognised for this detector \u2014 see raw evidence below.")

    with st.expander("Evidence"):
        source_rows = evidence.get("source_rows") or []
        if source_rows:
            st.markdown("**Linked source records**")
            st.dataframe(pd.DataFrame(source_rows), hide_index=True, width="stretch")
        else:
            st.caption("No linked source rows were attached to this finding.")
        st.markdown("**Raw evidence**")
        st.json(evidence, expanded=False)

    with st.expander("Peer context"):
        if detector == "fast_closure" and evidence.get("baseline_q1_minutes") is not None:
            obs = evidence.get("time_to_close_minutes", 0) or 0
            q1 = evidence.get("baseline_q1_minutes", 0) or 0
            chart_df = pd.DataFrame({"minutes to close": [obs, q1]}, index=["This alert", "Severity Q1 baseline"])
            st.bar_chart(chart_df, width="stretch")
        elif detector == "low_coverage" and evidence.get("peer_median") is not None:
            obs = evidence.get("observed_count", 0) or 0
            median = evidence.get("peer_median", 0) or 0
            chart_df = pd.DataFrame({"alerts (window)": [obs, median]}, index=["This asset", "Peer median"])
            st.bar_chart(chart_df, width="stretch")
        else:
            st.caption("No statistical baseline for this detector \u2014 it is a deterministic rule, not a distribution comparison.")

    with st.expander("History"):
        prev_name = get_previous_run(rp.name)
        if prev_name:
            prev_flags = get_flags_df(run_paths(prev_name))
            recurring_keys = compute_recurrence_keys(prev_flags)
            key = flag_recurrence_key(row)
            if key in recurring_keys:
                st.warning(f"\U0001F501 This same condition also fired for this entity in the prior run `{prev_name}` \u2014 it has not been corrected since.")
            else:
                st.caption(f"Did not fire for this entity/detector in the prior run (`{prev_name}`).")
        else:
            st.caption("No prior run available for this entity to compare against.")

    st.divider()
    st.markdown("**Disposition**")
    decision_options = list(DISPOSITION_BADGE.keys())
    decision_labels = {k: v[0] for k, v in DISPOSITION_BADGE.items()}
    default_index = 0
    if existing and existing.get("decision") in decision_options:
        default_index = decision_options.index(existing["decision"])
    decision = st.radio(
        "Decision", decision_options, index=default_index,
        format_func=lambda k: decision_labels[k], horizontal=True, key=f"decision_{flag_id}",
    )
    note = st.text_area("Note", value=(existing.get("note", "") if existing else ""), key=f"note_{flag_id}")

    save_col, queue_col = st.columns(2)
    with save_col:
        if st.button("Save disposition", type="primary", width="stretch", key=f"save_{flag_id}"):
            append_disposition(rp, flag_id, row["entity_id"], decision, note, st.session_state.examiner_name)
            st.success("Disposition saved to the audit log.")
            st.rerun()
    with queue_col:
        if st.button("Add to review queue", width="stretch", key=f"queue_{flag_id}"):
            added = add_to_review_queue(rp, "finding", flag_id, row["entity_id"], row["rationale"][:140], float(row["severity_weight"]))
            st.toast("Added to review queue." if added else "Already on the review queue.")

    if existing:
        st.caption(f"Last saved by {existing.get('examiner', '\u2013')} at {str(existing.get('recorded_at', ''))[:19]} UTC")


# ────────────────────────────────────────────────────────────────────────
# Page: Run assessment — the intake + pipeline-execution workflow
# (08-streamlit-workbench.md \u00a7"Run assessment", CLI args from
# 03-cli-and-workflows.md)
# ────────────────────────────────────────────────────────────────────────


def page_run_assessment() -> None:
    st.title("Run assessment")
    st.caption("Generate a synthetic submission or upload CSE exports, then run ingest \u2192 detect \u2192 "
               "score \u2192 report as one pipeline. Nothing here duplicates SAT-SA's analytics \u2014 every "
               "step below calls `python -m sat_sa.cli` directly.")

    ok, msg = cli_status()
    if not ok:
        st.error("Can't reach the SAT-SA CLI (`python -m sat_sa.cli --help` failed). Run this app from an "
                 "environment where the `sat_sa` package is installed, then use **Refresh data** in the sidebar.")
        with st.expander("Details"):
            st.code(msg or "(no output captured)", language="text")
        return

    col_name, col_mode = st.columns([2, 3])
    with col_name:
        run_name_input = st.text_input("Run name", value=default_run_name(),
                                        help="Folder name under runs/. Letters, numbers, - and _ only.")
        clean_name = sanitize_run_name(run_name_input)
        if clean_name != run_name_input.strip():
            st.caption(f"Will be saved as `{clean_name}`")
        existing_runs = list_runs()
        if clean_name in existing_runs:
            st.warning(f"`{clean_name}` already exists \u2014 starting again overwrites its source/normalized/results.")

    with col_mode:
        source_mode = st.radio("Data source", ["Synthetic data", "Upload CSE submissions"], horizontal=True)

    uploaded: dict[str, Any] = {}
    missing: list[str] = []
    entities_n = alerts_per_entity = seed = 0
    anomaly_rate = 0.15

    if source_mode == "Synthetic data":
        preset_name = st.selectbox("Preset", list(PRESETS.keys()))
        preset = PRESETS[preset_name]
        default_per_entity = max(1, preset["alerts"] // preset["entities"])
        c1, c2, c3 = st.columns(3)
        entities_n = c1.number_input("CSEs", min_value=4, value=preset["entities"], step=1)
        alerts_per_entity = c2.number_input("Alerts per CSE", min_value=1, value=default_per_entity, step=100)
        anomaly_rate = c3.slider("Anomaly rate", 0.01, 1.0, preset["anomaly_rate"])
        c4, c5 = st.columns(2)
        seed = c4.number_input("Seed", min_value=0, value=42, step=1)
        total_alerts = int(entities_n) * int(alerts_per_entity) + 2 * max(1, round(entities_n * anomaly_rate))
        c5.metric("Alerts to generate", f"{total_alerts:,}")
        st.caption(f"Preset intent: {preset['use']}.")
    else:
        st.caption("Upload all five submission files \u2014 `cases.csv`/`escalations.csv` may be valid empty files, "
                   "but must still be present.")
        cols = st.columns(5)
        for col, label in zip(cols, UPLOAD_LABELS):
            uploaded[label] = col.file_uploader(label, type="csv", key=f"upload_{label}")
        missing = [label for label in UPLOAD_LABELS if uploaded.get(label) is None]
        if missing:
            st.info("Still needed: " + ", ".join(missing))

    with st.expander("Advanced: detectors, thresholds, weights & runtime"):
        st.markdown("**Detectors**")
        detectors = st.multiselect("Run these detector groups", ["execution_gaps", "negative_space"],
                                    default=["execution_gaps", "negative_space"])
        st.markdown("**Thresholds**")
        t1, t2, t3 = st.columns(3)
        fast_closure_k = t1.number_input("Fast-closure k (\u00d7IQR)", min_value=0.1, value=DEFAULT_THRESHOLDS["fast_closure_k"], step=0.1)
        coverage_window_days = t2.number_input("Coverage window (days)", min_value=1, value=DEFAULT_THRESHOLDS["coverage_window_days"], step=1)
        coverage_threshold_pct = t3.slider("Coverage threshold (% of peer median)", 0.01, 1.0, DEFAULT_THRESHOLDS["coverage_threshold_pct"])
        st.markdown("**Scoring weights**")
        w1, w2, w3 = st.columns(3)
        w_fast = w1.number_input("Fast closure", min_value=0.0, value=DEFAULT_WEIGHTS["fast_closure"], step=0.5)
        w_esc = w2.number_input("No escalation", min_value=0.0, value=DEFAULT_WEIGHTS["no_escalation"], step=0.5)
        w_cov = w3.number_input("Low coverage", min_value=0.0, value=DEFAULT_WEIGHTS["low_coverage"], step=0.5)
        st.markdown("**Runtime**")
        r1, r2, r3, r4 = st.columns(4)
        batch_size = r1.number_input("Batch size", min_value=0, value=0, step=1000, help="0 = automatic")
        workers = r2.number_input("Workers", min_value=0, value=0, step=1, help="0 = automatic")
        adaptive_pipeline = r3.toggle("Adaptive runtime", value=True)
        healthcheck_interval = r4.number_input("Health-check interval", min_value=1, value=4, step=1)

    disabled = source_mode == "Upload CSE submissions" and bool(missing)
    start = st.button("Start assessment", type="primary", disabled=disabled, width="stretch")

    if start:
        rp = run_paths(clean_name)
        rp.root.mkdir(parents=True, exist_ok=True)
        weights = {"fast_closure": w_fast, "no_escalation": w_esc, "low_coverage": w_cov}
        thresholds = {"fast_closure_k": fast_closure_k, "coverage_window_days": coverage_window_days,
                      "coverage_threshold_pct": coverage_threshold_pct}
        config_path = write_detector_config(rp, thresholds, weights)
        adaptive_flag = "--adaptive" if adaptive_pipeline else "--no-adaptive"

        status = st.status("Running SAT-SA pipeline\u2026", expanded=True)
        log_area = status.empty()
        ok_all = True

        if source_mode == "Synthetic data":
            status.update(label="Generating synthetic submission\u2026")
            args = ["generate-synth", "--entities", str(int(entities_n)), "--alerts-per-entity", str(int(alerts_per_entity)),
                    "--seed", str(int(seed)), "--anomaly-rate", str(anomaly_rate), "--batch-size", str(int(batch_size)),
                    adaptive_flag, "--healthcheck-interval", str(int(healthcheck_interval)), "--out", str(rp.source)]
            rc, _ = run_cli_streaming(args, log_area)
            ok_all = rc == 0
        else:
            rp.source.mkdir(parents=True, exist_ok=True)
            for label, upload in uploaded.items():
                if upload is not None:
                    (rp.source / label).write_bytes(upload.getvalue())
            log_area.code(f"Saved {len(uploaded)} uploaded files to {rp.source}", language="text")

        if ok_all:
            status.update(label="Validating & normalizing submission\u2026")
            args = ["ingest", "--input", str(rp.source), "--format", "csv",
                    "--batch-size", str(int(batch_size)), "--workers", str(int(workers)),
                    adaptive_flag, "--healthcheck-interval", str(int(healthcheck_interval)), "--out", str(rp.normalized)]
            rc, _ = run_cli_streaming(args, log_area)
            ok_all = rc == 0

        if ok_all and not detectors:
            st.warning("No detectors selected \u2014 stopping after ingest. Findings, scoring, and reports need at least one detector group.")
            ok_all = False

        if ok_all:
            status.update(label="Running detectors\u2026")
            rp.results.mkdir(parents=True, exist_ok=True)
            args = ["detect", "--data", str(rp.normalized), "--detectors", ",".join(detectors),
                    "--config", str(config_path), "--batch-size", str(int(batch_size)), "--workers", str(int(workers)),
                    adaptive_flag, "--healthcheck-interval", str(int(healthcheck_interval)), "--out", str(rp.flags_json)]
            rc, _ = run_cli_streaming(args, log_area)
            ok_all = rc == 0

        if ok_all:
            status.update(label="Scoring entities\u2026")
            args = ["score", "--flags", str(rp.flags_json), "--config", str(config_path), "--out", str(rp.entity_scores_csv)]
            rc, _ = run_cli_streaming(args, log_area)
            ok_all = rc == 0

        if ok_all:
            status.update(label="Building report\u2026")
            args = ["report", "--scores", str(rp.entity_scores_csv), "--flags", str(rp.flags_json),
                    "--format", "json", "--out", str(rp.report_json)]
            rc, _ = run_cli_streaming(args, log_area)
            ok_all = rc == 0

        if ok_all and source_mode == "Synthetic data" and rp.ground_truth_parquet.exists():
            status.update(label="Validating against synthetic ground truth\u2026")
            args = ["validate", "--flags", str(rp.flags_json), "--synth-ground-truth", str(rp.ground_truth_parquet)]
            rc, out = run_cli_streaming(args, log_area)
            try:
                rp.validation_txt.write_text(out, encoding="utf-8")
            except OSError:
                pass

        if ok_all:
            status.update(label="Assessment complete.", state="complete")
            st.session_state.active_run = clean_name
            st.cache_data.clear()
            st.success(f"Run `{clean_name}` is ready.")
            validation_text = get_validation_text(rp)
            if validation_text:
                with st.expander("Synthetic validation (precision / recall / F1 by detector)", expanded=True):
                    st.code(validation_text, language="text")
                    st.caption("Measures recovery of deliberately injected conditions only \u2014 not real-world effectiveness.")
            if st.button("Open portfolio \u2192", type="primary"):
                goto("portfolio")
        else:
            status.update(label="Assessment stopped \u2014 see log above for the failing step.", state="error")

    st.divider()
    with st.expander("How runs are organised on disk"):
        st.code(
            "runs/<run-name>/\n"
            "  source/       raw submission (uploaded CSVs, or generate-synth output)\n"
            "  normalized/   entities/assets/alerts/cases/escalations.parquet + rejects.json\n"
            "  results/      flags.json, alert_volumes.json, entity_scores.csv, report.json\n",
            language="text",
        )
        st.caption("The CLI has no built-in concept of a recurring \u201ccycle\u201d \u2014 each run directory here is this "
                   "workbench's stand-in for one periodic submission window, and pages that compare \u201cthis cycle vs "
                   "last\u201d are really comparing the active run to the next-most-recent run directory.")


# ────────────────────────────────────────────────────────────────────────
# Page: Portfolio overview (home / landing page)
# ────────────────────────────────────────────────────────────────────────


def page_portfolio() -> None:
    st.title("Portfolio overview")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return

    rp = run_paths(active)
    status = run_status(active)
    if status != "scored":
        label, _ = STATUS_LABELS.get(status, ("Unknown", "gray"))
        st.info(f"Run `{active}` is not fully scored yet ({label}). Finish it on **Run assessment**, "
                "or pick a different run in the sidebar.")
        return

    tables = get_normalized_tables(rp)
    entities = tables.get("entities", pd.DataFrame())
    scores_df = get_entity_scores(rp)
    flags_df = get_flags_df(rp)
    volumes = get_alert_volumes(rp)

    if entities.empty or scores_df.empty:
        st.info("This run has no entities or scores yet.")
        return

    metrics = compute_entity_metrics(tables, volumes)
    deviation = compute_peer_deviation(tables, volumes)
    thresholds, weights = load_run_config(rp)

    merged = entities[["entity_id"]].merge(scores_df, on="entity_id", how="left")
    merged = merged.merge(metrics, on="entity_id", how="left")
    merged = merged.merge(deviation, on="entity_id", how="left")
    merged["risk_score"] = merged["risk_score"].fillna(0.0)
    merged["flag_counts"] = merged["flag_counts"].apply(lambda v: v if isinstance(v, dict) else {})
    merged["alert_volume"] = merged["alert_volume"].fillna(0)
    merged["peer_deviation_pct"] = merged["peer_deviation_pct"].fillna(0.0)

    components = merged.apply(
        lambda r: decompose_score(r["flag_counts"], r["alert_volume"], weights), axis=1, result_type="expand")
    merged = pd.concat([merged, components], axis=1)

    prev_name = get_previous_run(active)
    prev_scores = get_entity_scores(run_paths(prev_name)) if prev_name else pd.DataFrame()
    prev_flags = get_flags_df(run_paths(prev_name)) if prev_name else pd.DataFrame()
    prev_entities_flagged = set(prev_flags["entity_id"]) if not prev_flags.empty else set()
    cur_entities_flagged = set(flags_df["entity_id"]) if not flags_df.empty else set()
    merged["new_flag"] = merged["entity_id"].isin(cur_entities_flagged - prev_entities_flagged)

    trend = portfolio_trend_map(list(merged["entity_id"]))
    merged["trend"] = merged["entity_id"].map(trend)

    eg_entities = set(flags_df[flags_df["family"] == "EG"]["entity_id"]) if not flags_df.empty else set()
    ns_entities = set(flags_df[flags_df["family"] == "NS"]["entity_id"]) if not flags_df.empty else set()
    no_data_entities = merged[merged["alert_volume"] <= 0]

    avg_risk = float(merged["risk_score"].mean())
    prev_avg_risk = float(prev_scores["risk_score"].mean()) if not prev_scores.empty else None
    delta_risk = None if prev_avg_risk is None else avg_risk - prev_avg_risk

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("CSEs assessed", len(entities), border=True)
    m2.metric("Flagged \u2014 execution gap", len(eg_entities), border=True)
    m3.metric("Flagged \u2014 negative space", len(ns_entities), border=True)
    m4.metric("No alert data", len(no_data_entities), border=True)
    m5.metric(
        "Average portfolio risk", f"{avg_risk:.2f}",
        delta=(f"{delta_risk:+.2f}" if delta_risk is not None else None),
        delta_color="inverse",
        border=True,
        help=(f"vs previous run `{prev_name}`" if prev_name else "No previous run to compare against yet."),
    )

    action_cols = st.columns(3)
    if action_cols[0].button("View all findings \u2192", width="stretch"):
        goto("findings_feed")
    if action_cols[1].button("Data health \u2192", width="stretch"):
        goto("data_health")
    if action_cols[2].button("Portfolio summary report \u2192", width="stretch"):
        goto("reports")

    with st.expander("Filters"):
        f1, f2, f3, f4 = st.columns(4)
        sectors = sorted(s for s in merged["sector"].dropna().unique()) if "sector" in merged.columns else []
        sel_sectors = f1.multiselect("Sector", sectors)
        max_risk = float(merged["risk_score"].max()) if not merged.empty else 1.0
        min_risk = f2.slider("Minimum risk", 0.0, max(max_risk, 1.0), 0.0)
        new_only = f3.toggle("New this cycle only", value=False, disabled=(prev_name is None))
        status_choice = f4.selectbox("Submission status", ["All", "Has alerts", "No alert data"])

    view = merged.copy()
    if sel_sectors:
        view = view[view["sector"].isin(sel_sectors)]
    view = view[view["risk_score"] >= min_risk]
    if status_choice == "Has alerts":
        view = view[view["alert_volume"] > 0]
    elif status_choice == "No alert data":
        view = view[view["alert_volume"] <= 0]
    if new_only and prev_name:
        view = view[view["new_flag"]]

    view = view.sort_values("risk_score", ascending=False).reset_index(drop=True)
    display_df = view[[
        "entity_id", "name", "sector", "risk_score", "eg_component", "ns_component",
        "peer_deviation_pct", "trend", "new_flag", "alert_volume",
    ]].rename(columns={
        "entity_id": "Entity ID", "name": "Entity", "sector": "Sector", "risk_score": "Risk",
        "eg_component": "EG score", "ns_component": "NS score", "peer_deviation_pct": "Peer deviation",
        "trend": "Trend", "new_flag": "New", "alert_volume": "Alerts",
    })

    st.caption(f"{len(display_df)} of {len(merged)} entities shown \u00b7 click a row to open its profile.")
    scale_max = max(float(display_df["Risk"].max()) if not display_df.empty else 1.0, 1.0)
    event = st.dataframe(
        display_df,
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key="portfolio_table",
        column_config={
            "Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=scale_max, format="%.2f"),
            "EG score": st.column_config.NumberColumn("EG score", format="%.2f"),
            "NS score": st.column_config.NumberColumn("NS score", format="%.2f"),
            "Peer deviation": st.column_config.ProgressColumn("Peer deviation", min_value=0, max_value=1, format="%.0f%%"),
            "Trend": st.column_config.LineChartColumn("4-run trend", y_min=0),
            "New": st.column_config.CheckboxColumn("New", disabled=True),
            "Alerts": st.column_config.NumberColumn("Alerts", format="%d"),
        },
    )
    if event.selection.rows:
        chosen_id = display_df.iloc[event.selection.rows[0]]["Entity ID"]
        set_active_entity(chosen_id)
        goto("entity_profile", entity_id=chosen_id)


# ────────────────────────────────────────────────────────────────────────
# Page: Entity profile
# ────────────────────────────────────────────────────────────────────────


def page_entity_profile() -> None:
    st.title("Entity profile")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return
    rp = run_paths(active)
    if run_status(active) not in ("detected", "scored"):
        st.info("This run hasn't been through detection yet. Finish it on **Run assessment** first.")
        return

    tables = get_normalized_tables(rp)
    entities = tables.get("entities", pd.DataFrame())
    if entities.empty:
        st.info("No entities in this run.")
        return

    entity_ids = list(entities["entity_id"])
    labels = {r["entity_id"]: f"{r['entity_id']} \u2014 {r['name']}" for _, r in entities.iterrows()}
    qp_entity = st.query_params.get("entity_id")
    default_entity = st.session_state.active_entity_id or qp_entity
    if default_entity not in entity_ids:
        default_entity = entity_ids[0]
    chosen = st.selectbox("Entity", entity_ids, index=entity_ids.index(default_entity),
                           format_func=lambda e: labels.get(e, e))
    set_active_entity(chosen)

    entity_row = entities[entities["entity_id"] == chosen].iloc[0]
    scores_df = get_entity_scores(rp)
    score_match = scores_df[scores_df["entity_id"] == chosen]
    flags_df = get_flags_df(rp)
    entity_flags = flags_df[flags_df["entity_id"] == chosen] if not flags_df.empty else flags_df
    volumes = get_alert_volumes(rp)
    thresholds, weights = load_run_config(rp)

    risk_score = float(score_match.iloc[0]["risk_score"]) if not score_match.empty else 0.0
    rank = int(score_match.iloc[0]["priority_rank"]) if not score_match.empty else None
    flag_counts = score_match.iloc[0]["flag_counts"] if not score_match.empty else {}
    alert_volume = volumes.get(chosen, int(score_match.iloc[0]["alert_volume"]) if not score_match.empty else 0)
    scale_max = max(float(scores_df["risk_score"].max()) if not scores_df.empty else 1.0, 1.0)
    status_word = risk_status_word(risk_score, scale_max)

    header_l, header_r = st.columns([3, 1])
    with header_l:
        st.markdown(f"## {entity_row['name']}")
        st.caption(f"`{chosen}` \u00b7 sector: {entity_row.get('sector') or '\u2013'} \u00b7 peer group: {entity_row['peer_group']}")
    with header_r:
        st.metric("Risk score", f"{risk_score:.2f}", border=True)
        st.badge(f"Priority #{rank}" if rank else "Unranked", color=STATUS_BADGE_COLOR.get(status_word, "gray"))

    action_cols = st.columns(3)
    if action_cols[0].button("Compare to peers \u2192", width="stretch"):
        goto("peer_benchmarking", entity_id=chosen)
    if action_cols[1].button("Generate entity report \u2192", width="stretch"):
        goto("reports", entity_id=chosen)
    if action_cols[2].button("View submission status \u2192", width="stretch"):
        goto("data_health")

    tab_overview, tab_alerts, tab_coverage, tab_findings, tab_history = st.tabs(
        ["Overview", "Alerts & cases", "Coverage", "Findings", "History"])

    with tab_overview:
        components = decompose_score(flag_counts, alert_volume, weights)
        comp_df = pd.DataFrame({"score": [components["eg_component"], components["ns_component"]]},
                                index=["Execution gap", "Negative space"])
        st.bar_chart(comp_df, width="stretch")

        metrics_all = compute_entity_metrics(tables, volumes)
        sector_metrics = metrics_all[metrics_all["peer_group"] == entity_row["peer_group"]]
        this_metrics = metrics_all[metrics_all["entity_id"] == chosen]
        avg_closure = this_metrics.iloc[0]["avg_case_closure_hours"] if not this_metrics.empty else None
        esc_rate = float(this_metrics.iloc[0]["escalation_rate"]) if not this_metrics.empty else 0.0
        sector_median_closure = sector_metrics["avg_case_closure_hours"].median() if not sector_metrics.empty else None
        sector_median_esc = sector_metrics["escalation_rate"].median() if not sector_metrics.empty else None

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Alert volume", f"{int(alert_volume):,}")
        k2.metric("Avg case closure", fmt_hours(avg_closure),
                  help=(f"Sector median: {fmt_hours(sector_median_closure)}" if sector_median_closure is not None else None))
        k3.metric("Escalation rate", fmt_pct(esc_rate),
                  help=(f"Sector median: {fmt_pct(sector_median_esc)}" if sector_median_esc is not None else None))
        crit_count = int(this_metrics.iloc[0]["critical_asset_count"]) if not this_metrics.empty else 0
        asset_count = int(this_metrics.iloc[0]["asset_count"]) if not this_metrics.empty else 0
        k4.metric("Asset inventory", asset_count, help=f"{crit_count} critical")

    with tab_alerts:
        alerts = tables.get("alerts", pd.DataFrame())
        cases = tables.get("cases", pd.DataFrame())
        entity_alerts = alerts[alerts["entity_id"] == chosen] if not alerts.empty else alerts
        entity_cases = cases[cases["entity_id"] == chosen] if not cases.empty else cases

        st.markdown(f"**Alerts** ({len(entity_alerts)})")
        if not entity_alerts.empty:
            flagged_ids = set(entity_flags["reference_id"]) if not entity_flags.empty else set()
            fcol1, fcol2 = st.columns([2, 1])
            search = fcol1.text_input("Filter alerts", key="alert_search", placeholder="alert ID, category, disposition\u2026")
            sev_options = sorted(entity_alerts["severity"].dropna().unique()) if "severity" in entity_alerts.columns else []
            sev_filter = fcol2.multiselect("Severity", sev_options, key="alert_sev_filter")

            view_alerts = entity_alerts.copy()
            view_alerts["flagged"] = view_alerts["alert_id"].isin(flagged_ids)
            if search:
                needle = search.lower()
                view_alerts = view_alerts[view_alerts.astype(str).apply(
                    lambda r: needle in " ".join(r.values).lower(), axis=1)]
            if sev_filter:
                view_alerts = view_alerts[view_alerts["severity"].isin(sev_filter)]

            show_cols = [c for c in ["alert_id", "asset_id", "category", "severity", "disposition",
                                      "escalated", "created_at", "closed_at", "flagged"] if c in view_alerts.columns]
            event_a = st.dataframe(view_alerts[show_cols], hide_index=True, width="stretch",
                                    on_select="rerun", selection_mode="single-row", key="entity_alerts_table")
            if event_a.selection.rows:
                sel_row = view_alerts.iloc[event_a.selection.rows[0]]
                with st.expander(f"Alert {sel_row['alert_id']}", expanded=True):
                    st.json(sel_row.to_dict())
        else:
            st.caption("No alerts for this entity.")

        st.markdown(f"**Cases** ({len(entity_cases)})")
        if not entity_cases.empty:
            st.dataframe(entity_cases, hide_index=True, width="stretch")
        else:
            st.caption("No cases for this entity.")

    with tab_coverage:
        coverage = compute_asset_coverage(tables, int(thresholds["coverage_window_days"]), float(thresholds["coverage_threshold_pct"]))
        assets = tables.get("assets", pd.DataFrame())
        entity_assets = assets[assets["entity_id"] == chosen] if not assets.empty else assets
        if entity_assets.empty:
            st.caption("No assets recorded for this entity.")
        else:
            cov_lookup = dict(zip(coverage["asset_id"], coverage["status"])) if not coverage.empty else {}
            status_text = {"red": "Low", "amber": "Below median", "green": "Normal", "gray": "No data"}
            display = entity_assets.copy()
            display["telemetry"] = display["asset_id"].map(
                lambda a: status_row_text(cov_lookup.get(a, "gray"), status_text[cov_lookup.get(a, "gray")]))
            crit_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            display["_order"] = display["criticality"].map(crit_order).fillna(9)
            display = display.sort_values("_order").drop(columns="_order")
            cols_show = [c for c in ["asset_id", "criticality", "asset_type", "telemetry"] if c in display.columns]
            st.dataframe(display[cols_show], hide_index=True, width="stretch")
            st.caption("Telemetry status compares each critical asset's recent alert volume against its peer critical-asset "
                       "median for context. The Findings tab remains the authoritative list of what was actually flagged.")

    with tab_findings:
        if entity_flags.empty:
            st.caption("No findings for this entity in this run.")
        else:
            render_findings_table(entity_flags, rp, key_prefix="entity_findings")

    with tab_history:
        hist = entity_score_history(chosen)
        if hist.empty:
            st.caption("No scored history yet for this entity across runs.")
        else:
            st.line_chart(hist.set_index("run")[["risk_score"]], width="stretch")
        prev_name = get_previous_run(active)
        if prev_name:
            prev_flags = get_flags_df(run_paths(prev_name))
            recurring_keys = compute_recurrence_keys(prev_flags)
            if not entity_flags.empty:
                recurring_now = entity_flags[entity_flags.apply(lambda r: flag_recurrence_key(r) in recurring_keys, axis=1)]
                if not recurring_now.empty:
                    st.warning(f"\U0001F501 {len(recurring_now)} finding(s) recur from `{prev_name}` \u2014 not corrected since.")
                    st.dataframe(recurring_now[["flag_id", "detector", "rationale"]], hide_index=True, width="stretch")
                else:
                    st.caption("No recurring findings from the prior run.")
        else:
            st.caption("No prior run to compare history against.")


# ────────────────────────────────────────────────────────────────────────
# Shared findings table renderer (used by Findings feed, Entity profile,
# and the Detector library's "fired this cycle" drill-down)
# ────────────────────────────────────────────────────────────────────────


def render_findings_table(flags_subset: pd.DataFrame, rp: RunPaths, key_prefix: str) -> None:
    if flags_subset.empty:
        st.caption("No findings.")
        return

    prev_name = get_previous_run(rp.name)
    recurring_keys = compute_recurrence_keys(get_flags_df(run_paths(prev_name))) if prev_name else set()
    disp_map = latest_disposition_map(rp)

    display = flags_subset.copy()
    display["Detector"] = display["detector"].map(detector_short_label)
    display["Recurring"] = display.apply(lambda r: flag_recurrence_key(r) in recurring_keys, axis=1)
    display["Status"] = display["flag_id"].map(
        lambda fid: DISPOSITION_BADGE.get(disp_map[fid]["decision"], (disp_map[fid]["decision"], "gray"))[0]
        if fid in disp_map else "Pending review")
    display["Detected"] = display["generated_at"].apply(
        lambda d: d.strftime("%Y-%m-%d %H:%M") if pd.notna(d) else "\u2013")
    display = display.sort_values(["severity_weight", "Recurring"], ascending=[False, False]).reset_index(drop=True)

    show = display[["flag_id", "entity_id", "Detector", "severity_weight", "Detected", "Status", "Recurring", "rationale"]].rename(
        columns={"flag_id": "Finding ID", "entity_id": "Entity", "severity_weight": "Weight", "rationale": "Rationale"})

    event = st.dataframe(
        show, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
        key=f"{key_prefix}_table",
        column_config={
            "Weight": st.column_config.NumberColumn("Weight", format="%.1f"),
            "Recurring": st.column_config.CheckboxColumn("Recurring", disabled=True),
        },
    )
    st.caption("Open a finding to see the evidence, record a disposition, or add it to the review queue.")
    if event.selection.rows:
        fid = show.iloc[event.selection.rows[0]]["Finding ID"]
        finding_detail_dialog(fid, rp)


# ────────────────────────────────────────────────────────────────────────
# Page: Findings feed
# ────────────────────────────────────────────────────────────────────────


def page_findings_feed() -> None:
    st.title("Findings feed")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return
    rp = run_paths(active)
    flags_df = get_flags_df(rp)
    if flags_df.empty:
        st.info("No findings in this run yet \u2014 run detection on **Run assessment**, or pick a different run.")
        return

    tables = get_normalized_tables(rp)
    entities = tables.get("entities", pd.DataFrame())
    if not entities.empty:
        keep_cols = [c for c in ["entity_id", "name", "sector"] if c in entities.columns]
        flags_df = flags_df.merge(entities[keep_cols], on="entity_id", how="left")

    qp_finding = st.query_params.get("finding_id")
    if qp_finding:
        finding_detail_dialog(qp_finding, rp)

    with st.expander("Filters", expanded=bool(st.session_state.get("findings_rule_filter"))):
        c1, c2, c3, c4 = st.columns(4)
        entity_filter = c1.multiselect("Entity", sorted(flags_df["entity_id"].unique()), key="findings_entity_filter")
        sector_options = sorted(flags_df["sector"].dropna().unique()) if "sector" in flags_df.columns else []
        sector_filter = c2.multiselect("Sector", sector_options, key="findings_sector_filter")
        rule_filter = c3.multiselect("Detector rule", sorted(flags_df["detector"].unique()),
                                      format_func=detector_short_label, key="findings_rule_filter")
        prev_name = get_previous_run(active)
        recurring_only = c4.toggle("Recurring only", value=False, disabled=(prev_name is None))

    view = flags_df.copy()
    if entity_filter:
        view = view[view["entity_id"].isin(entity_filter)]
    if sector_filter:
        view = view[view["sector"].isin(sector_filter)]
    if rule_filter:
        view = view[view["detector"].isin(rule_filter)]
    if recurring_only and prev_name:
        recurring_keys = compute_recurrence_keys(get_flags_df(run_paths(prev_name)))
        view = view[view.apply(lambda r: flag_recurrence_key(r) in recurring_keys, axis=1)]

    tab_eg, tab_ns = st.tabs(["Execution gaps (EG)", "Negative space (NS)"])
    with tab_eg:
        render_findings_table(view[view["family"] == "EG"], rp, key_prefix="findings_eg")
    with tab_ns:
        render_findings_table(view[view["family"] == "NS"], rp, key_prefix="findings_ns")


# ────────────────────────────────────────────────────────────────────────
# Page: Peer benchmarking
# ────────────────────────────────────────────────────────────────────────

BENCHMARK_METRICS = {
    "Alert volume": "alert_volume",
    "Avg case closure (hours)": "avg_case_closure_hours",
    "Escalation rate": "escalation_rate",
    "Critical asset count": "critical_asset_count",
}


def page_peer_benchmarking() -> None:
    st.title("Peer benchmarking")
    st.caption("Peer group \u2014 not sector \u2014 is the actual benchmarking cohort SAT-SA uses "
               "(sector is descriptive metadata only). Comparisons never cross peer groups.")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return
    rp = run_paths(active)
    tables = get_normalized_tables(rp)
    entities = tables.get("entities", pd.DataFrame())
    if entities.empty:
        st.info("No entities in this run.")
        return

    volumes = get_alert_volumes(rp)
    metrics = compute_entity_metrics(tables, volumes)

    entity_ids = list(entities["entity_id"])
    default_entity = st.session_state.active_entity_id or st.query_params.get("entity_id")
    if default_entity not in entity_ids:
        default_entity = entity_ids[0]

    c1, c2 = st.columns(2)
    entity_choice = c1.selectbox("Entity", entity_ids, index=entity_ids.index(default_entity),
                                  format_func=lambda e: f"{e} \u2014 {entities.loc[entities['entity_id']==e,'name'].iloc[0]}")
    set_active_entity(entity_choice)
    metric_label = c2.selectbox("Metric", list(BENCHMARK_METRICS.keys()))
    metric_col = BENCHMARK_METRICS[metric_label]

    peer_groups = sorted(entities["peer_group"].dropna().unique())
    auto_peer_group = entities.loc[entities["entity_id"] == entity_choice, "peer_group"].iloc[0]
    peer_group_choice = st.selectbox("Peer group", peer_groups,
                                      index=peer_groups.index(auto_peer_group) if auto_peer_group in peer_groups else 0)

    scope = metrics[metrics["peer_group"] == peer_group_choice].copy()
    scope = scope.dropna(subset=[metric_col])
    if scope.empty:
        st.info("No data for this metric within the selected peer group.")
        return

    if HAS_PLOTLY:
        fig = go.Figure()
        fig.add_trace(go.Box(
            y=scope[metric_col], name=peer_group_choice, boxpoints="all", jitter=0.4, pointpos=-1.8,
            marker=dict(color="#8A93A3"), line=dict(color="#1F6F8B"), fillcolor="rgba(31,111,139,0.12)",
        ))
        entity_val = scope.loc[scope["entity_id"] == entity_choice, metric_col]
        if not entity_val.empty:
            fig.add_trace(go.Scatter(
                x=[peer_group_choice], y=[entity_val.iloc[0]], mode="markers",
                marker=dict(size=16, color="#C4432B", symbol="diamond", line=dict(width=1, color="white")),
                name=entity_choice,
            ))
        fig.update_layout(showlegend=False, height=380, margin=dict(l=10, r=10, t=10, b=10),
                           yaxis_title=metric_label)
        st.plotly_chart(fig, width="stretch")
    else:
        st.caption("Install `plotly` for a box-plot view; showing a bar comparison instead.")
        chart_df = scope.set_index("entity_id")[[metric_col]].sort_values(metric_col, ascending=False)
        st.bar_chart(chart_df, width="stretch")

    bench = peer_benchmark(scope, "entity_id", metric_col, "peer_group")
    if bench.empty:
        return
    bench = bench.merge(entities[["entity_id", "name"]], on="entity_id", how="left")
    bench = bench.sort_values(metric_col, ascending=False).reset_index(drop=True)
    bench["Percentile"] = (bench["percentile_rank"] * 100).round(0).astype(int)
    bench["Entity"] = bench.apply(
        lambda r: f"\u2192 {r['name']} (this entity)" if r["entity_id"] == entity_choice else r["name"], axis=1)
    show = bench[["entity_id", "Entity", metric_col, "Percentile"]].rename(
        columns={"entity_id": "Entity ID", metric_col: metric_label})

    event = st.dataframe(show, hide_index=True, width="stretch", on_select="rerun",
                          selection_mode="single-row", key="peer_bench_table")
    if event.selection.rows:
        picked = show.iloc[event.selection.rows[0]]["Entity ID"]
        set_active_entity(picked)
        goto("entity_profile", entity_id=picked)


# ────────────────────────────────────────────────────────────────────────
# Page: Review queue
# ────────────────────────────────────────────────────────────────────────


def page_review_queue() -> None:
    st.title("Review queue")
    st.caption("Your prioritized to-do list, not an analysis surface \u2014 add items from the Findings feed or a "
               "finding's detail view. Stored locally per run, so it survives between sessions.")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return
    rp = run_paths(active)
    items = review_queue_items(rp)
    if not items:
        st.info("The review queue is empty.")
        return

    items = sorted(items, key=lambda i: i.get("priority_score", 0), reverse=True)
    df = pd.DataFrame(items)
    df["Added"] = pd.to_datetime(df["added_at"], errors="coerce", utc=True).dt.strftime("%Y-%m-%d %H:%M")
    display = df[["reference_type", "reference_id", "entity_id", "reason", "priority_score", "status", "assignee", "Added"]].rename(
        columns={"reference_type": "Type", "reference_id": "Reference", "entity_id": "Entity", "reason": "Reason",
                 "priority_score": "Priority", "status": "Status", "assignee": "Assignee"})

    edited = st.data_editor(
        display, hide_index=True, width="stretch", num_rows="fixed", key="review_queue_editor",
        column_config={
            "Type": st.column_config.TextColumn("Type", disabled=True),
            "Reference": st.column_config.TextColumn("Reference", disabled=True),
            "Entity": st.column_config.TextColumn("Entity", disabled=True),
            "Added": st.column_config.TextColumn("Added", disabled=True),
            "Priority": st.column_config.NumberColumn("Priority", format="%.1f"),
            "Status": st.column_config.SelectboxColumn("Status", options=["To review", "In progress", "Done"]),
        },
    )

    items_by_ref = {i["reference_id"]: dict(i) for i in items}
    changed = False
    for _, row in edited.iterrows():
        original = items_by_ref.get(row["Reference"])
        if not original:
            continue
        new_status = row["Status"]
        new_assignee = row.get("Assignee") or ""
        new_reason = row.get("Reason") or original.get("reason", "")
        new_priority = float(row.get("Priority") or 0)
        if (original.get("status") != new_status or original.get("assignee", "") != new_assignee
                or original.get("reason") != new_reason or original.get("priority_score") != new_priority):
            original["status"] = new_status
            original["assignee"] = new_assignee
            original["reason"] = new_reason
            original["priority_score"] = new_priority
            changed = True
    if changed:
        save_review_queue(rp, list(items_by_ref.values()))
        st.toast("Review queue updated.")

    st.divider()
    st.markdown("**Open an item**")
    options = [f"{i['reference_id']} \u2014 {i['entity_id']} \u2014 {i.get('reason','')[:60]}" for i in items]
    if options:
        oc1, oc2 = st.columns([4, 1])
        chosen_label = oc1.selectbox("Item to open", options, label_visibility="collapsed")
        chosen_item = items[options.index(chosen_label)]
        if oc2.button("Open \u2192", width="stretch"):
            if chosen_item["reference_type"] == "finding":
                finding_detail_dialog(chosen_item["reference_id"], rp)
            else:
                set_active_entity(chosen_item["entity_id"])
                goto("entity_profile", entity_id=chosen_item["entity_id"])
        if st.button(f"Open {chosen_item['entity_id']}'s profile \u2192", key="queue_open_entity"):
            set_active_entity(chosen_item["entity_id"])
            goto("entity_profile", entity_id=chosen_item["entity_id"])

    st.divider()
    with st.expander("Disposition audit log for this run"):
        log_df = all_dispositions(rp)
        if log_df.empty:
            st.caption("No dispositions recorded yet \u2014 save one from a finding's detail view.")
        else:
            log_df = log_df.sort_values("recorded_at", ascending=False)
            st.dataframe(log_df[["recorded_at", "examiner", "finding_id", "entity_id", "decision", "note"]],
                         hide_index=True, width="stretch")
            st.caption("Append-only: this is the audit trail an examiner's decisions are ultimately checked against.")


# ────────────────────────────────────────────────────────────────────────
# Page: Data health / submissions
# ────────────────────────────────────────────────────────────────────────


def page_data_health() -> None:
    st.title("Data health & submissions")
    st.caption("Separates \u201ccouldn't be validated / didn't land\u201d from \u201cwas ingested but is genuinely sparse\u201d "
               "\u2014 confusing the two is the fastest way to misjudge a negative-space finding.")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return
    rp = run_paths(active)
    tables = get_normalized_tables(rp)
    entities = tables.get("entities", pd.DataFrame())
    if entities.empty:
        st.info("No entities ingested in this run yet.")
        return

    rejects_df = get_rejects_df(rp)
    table_labels = {"assets": "Assets", "alerts": "Alerts", "cases": "Cases", "escalations": "Escalations"}

    matrix_rows = []
    for _, e in entities.iterrows():
        eid = e["entity_id"]
        row = {"Entity ID": eid, "Entity": e["name"]}
        for table_name, label in table_labels.items():
            t = tables.get(table_name, pd.DataFrame())
            count = int((t["entity_id"] == eid).sum()) if (not t.empty and "entity_id" in t.columns) else 0
            status = "red" if count == 0 else ("amber" if count <= 2 else "green")
            row[label] = status_row_text(status, str(count))
        reject_count = 0
        if not rejects_df.empty and "record" in rejects_df.columns:
            reject_count = int(rejects_df["record"].apply(
                lambda r: isinstance(r, dict) and r.get("entity_id") == eid).sum())
        row["Rejected"] = status_row_text("red" if reject_count > 0 else "green", str(reject_count))
        matrix_rows.append(row)

    st.dataframe(pd.DataFrame(matrix_rows), hide_index=True, width="stretch")
    st.caption("\U0001F534 zero records \u00b7 \U0001F7E1 sparse (1\u20132) \u00b7 \U0001F7E2 populated. SAT-SA validates at the "
               "submission-file level (all five tables must be present) rather than per entity, so this view shows "
               "how much data actually landed against each entity once ingested \u2014 the closest available proxy "
               "for per-entity coverage, not a literal submitted/not-submitted flag.")

    st.divider()
    st.markdown("### Ingestion quality \u2014 quarantined records")
    if rejects_df.empty:
        st.success("No rejected records in this run \u2014 every submitted row passed schema validation.")
    else:
        st.metric("Total quarantined rows", len(rejects_df))
        if "table" in rejects_df.columns:
            by_table = rejects_df.groupby("table").size().rename("Rejected rows").to_frame()
            st.bar_chart(by_table, width="stretch")
        show_cols = [c for c in ["source", "table", "row", "reason"] if c in rejects_df.columns]
        display_rejects = rejects_df[show_cols].copy()
        if "reason" in display_rejects.columns:
            display_rejects["reason"] = display_rejects["reason"].apply(
                lambda r: "; ".join(f"{e.get('loc')}: {e.get('msg')}" for e in r) if isinstance(r, list) else str(r))
        if "row" in display_rejects.columns:
            display_rejects = display_rejects.rename(columns={"row": "row (chunk-local index)"})
        st.dataframe(display_rejects, hide_index=True, width="stretch")
        st.caption("Row numbers are chunk-local for large CSV inputs, not absolute source line numbers "
                   "(02-data-and-storage-contract.md \u00a76) \u2014 use `source` + the record body to locate the row.")
        with st.expander("Raw rejected records"):
            st.json(rejects_df.to_dict(orient="records")[:200], expanded=False)


# ────────────────────────────────────────────────────────────────────────
# Page: Detector / rule library
# ────────────────────────────────────────────────────────────────────────


def page_detector_library() -> None:
    st.title("Detector library")
    st.caption("Documentation-as-data: what SAT-SA actually checks for, and the thresholds/weights in effect "
               "for the active run \u2014 so an auditor can verify the rule set without reading code.")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return
    rp = run_paths(active)
    thresholds, weights = load_run_config(rp)
    flags_df = get_flags_df(rp)
    fired_counts = flags_df["detector"].value_counts().to_dict() if not flags_df.empty else {}

    validation_text = get_validation_text(rp)
    if validation_text:
        with st.expander("Synthetic validation for this run (precision / recall / F1)"):
            st.code(validation_text, language="text")
            st.caption("Recovery of deliberately injected conditions only \u2014 see How it works for the full caveat.")

    rows = []
    for key, info in DETECTOR_INFO.items():
        if key == "fast_closure":
            threshold_str = f"k = {thresholds['fast_closure_k']} \u00d7 IQR (severity-specific)"
        elif key == "no_escalation":
            threshold_str = "n/a \u2014 deterministic rule"
        else:
            threshold_str = f"{fmt_pct(thresholds['coverage_threshold_pct'])} of peer median, {thresholds['coverage_window_days']}-day window"
        rows.append({
            "Rule ID": key, "Type": FAMILY_LABELS[info["family"]],
            "Supervisory question": info["question"], "Method": info["method"],
            "Threshold": threshold_str, "Weight": weights.get(key, DEFAULT_WEIGHTS[key]),
            "Fired this run": fired_counts.get(key, 0),
        })
    df = pd.DataFrame(rows)

    event = st.dataframe(
        df, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
        key="detector_lib_table",
        column_config={"Weight": st.column_config.NumberColumn("Weight", format="%.1f")},
    )
    st.caption("Select a rule to jump to its findings.")
    if event.selection.rows:
        rule = df.iloc[event.selection.rows[0]]["Rule ID"]
        st.session_state["findings_rule_filter"] = [rule]
        goto("findings_feed")


# ────────────────────────────────────────────────────────────────────────
# Page: Report center
# ────────────────────────────────────────────────────────────────────────


def render_entity_report_markdown(entry: dict, entities: pd.DataFrame) -> str:
    eid = entry.get("entity_id", "")
    name = eid
    if not entities.empty and eid in set(entities["entity_id"]):
        name = entities.loc[entities["entity_id"] == eid, "name"].iloc[0]
    flags = entry.get("flags") or entry.get("findings") or []
    lines = [
        f"# Entity assessment \u2014 {name} (`{eid}`)", "",
        f"**Risk score:** {entry.get('risk_score', '\u2013')} \u00b7 **Priority rank:** #{entry.get('priority_rank', '\u2013')}",
        "", f"## Findings ({len(flags)})", "",
    ]
    if not flags:
        lines.append("_No findings for this entity._")
    for f in flags:
        lines.append(f"- **{f.get('flag_id', '')}** ({detector_short_label(f.get('detector', ''))}): {f.get('rationale', '')}")
    return "\n".join(lines)


def render_portfolio_report_markdown(report: dict) -> str:
    summary = report.get("summary", {})
    lines = ["# Portfolio summary", "", f"Generated: {report.get('generated_at', '\u2013')}", ""]
    lines.append(f"- Entities analysed: {summary.get('analysed_entity_count', summary.get('entity_count', '\u2013'))}")
    lines.append(f"- Total flags: {summary.get('total_flag_count', summary.get('flag_count', '\u2013'))}")
    detector_counts = summary.get("detector_counts", {})
    if detector_counts:
        lines.append("\n## Findings by detector\n")
        for k, v in detector_counts.items():
            lines.append(f"- {detector_short_label(k)}: {v}")
    entities_list = sorted(report.get("entities", []), key=lambda x: x.get("priority_rank", 9999))
    lines.append("\n## Entities ranked by risk\n")
    for e in entities_list:
        lines.append(f"{e.get('priority_rank', '?')}. **{e.get('entity_id', '')}** \u2014 risk {e.get('risk_score', '?')}")
    return "\n".join(lines)


def page_reports() -> None:
    st.title("Report center")
    st.caption("Reports render the same findings, scores, and evidence already available elsewhere in the tool \u2014 "
               "nothing new is summarised here. PDF rendering isn't bundled with this offline build; Markdown, JSON, "
               "and CSV cover the same content and stay dependency-free.")

    active = st.session_state.get("active_run")
    if not active:
        empty_state_no_run()
        return
    rp = run_paths(active)
    if run_status(active) != "scored":
        st.info("This run needs to be scored before a report can be generated. Finish it on **Run assessment**.")
        return

    tables = get_normalized_tables(rp)
    entities = tables.get("entities", pd.DataFrame())
    flags_df = get_flags_df(rp)

    report_type = st.radio("Report type", ["Entity assessment", "Portfolio summary", "Findings export (CSV)"], horizontal=True)

    if report_type in ("Entity assessment", "Portfolio summary"):
        report = get_report(rp)
        if report is None:
            st.warning("`report.json` hasn't been built for this run yet.")
            if st.button("Build report now", type="primary"):
                status = st.status("Building report\u2026", expanded=True)
                log_area = status.empty()
                rc, _ = run_cli_streaming(
                    ["report", "--scores", str(rp.entity_scores_csv), "--flags", str(rp.flags_json),
                     "--format", "json", "--out", str(rp.report_json)], log_area)
                status.update(state="complete" if rc == 0 else "error")
                st.cache_data.clear()
                st.rerun()
            return

    if report_type == "Entity assessment":
        entity_ids = list(entities["entity_id"])
        default_entity = st.session_state.active_entity_id or st.query_params.get("entity_id")
        if default_entity not in entity_ids:
            default_entity = entity_ids[0] if entity_ids else None
        entity_choice = st.selectbox("Entity", entity_ids,
                                      index=entity_ids.index(default_entity) if default_entity in entity_ids else 0)
        entry = next((e for e in report.get("entities", []) if e.get("entity_id") == entity_choice), None)
        if entry is None:
            st.info("No report entry for this entity.")
            return
        md = render_entity_report_markdown(entry, entities)
        st.markdown(md)
        d1, d2 = st.columns(2)
        d1.download_button("Download Markdown", md, file_name=f"{entity_choice}_assessment.md",
                            mime="text/markdown", width="stretch")
        d2.download_button("Download JSON", json.dumps(entry, indent=2, default=str),
                            file_name=f"{entity_choice}_assessment.json", mime="application/json", width="stretch")

    elif report_type == "Portfolio summary":
        md = render_portfolio_report_markdown(report)
        st.markdown(md)
        d1, d2 = st.columns(2)
        d1.download_button("Download Markdown", md, file_name=f"{active}_portfolio_summary.md",
                            mime="text/markdown", width="stretch")
        d2.download_button("Download JSON", json.dumps(report, indent=2, default=str),
                            file_name=f"{active}_portfolio_summary.json", mime="application/json", width="stretch")

    else:  # Findings export (CSV)
        if flags_df.empty:
            st.info("No findings to export in this run.")
        else:
            export_df = flags_df.drop(columns=["family", "reference_id"], errors="ignore").copy()
            export_df["evidence"] = export_df["evidence"].apply(lambda e: json.dumps(e, default=str))
            csv_bytes = export_df.to_csv(index=False).encode("utf-8")
            st.download_button("Download findings CSV", csv_bytes, file_name=f"{active}_findings.csv",
                                mime="text/csv", type="primary")
            st.dataframe(flags_df[["flag_id", "entity_id", "detector", "severity_weight", "rationale"]],
                         hide_index=True, width="stretch")


# ────────────────────────────────────────────────────────────────────────
# Page: How it works
# ────────────────────────────────────────────────────────────────────────


def page_how_it_works() -> None:
    st.title("How SAT-SA works")
    st.caption("A concise explanation for demos and audits \u2014 everything below is a description of the real "
               "pipeline this workbench drives, not aspirational copy.")

    st.markdown("""
SAT-SA is a **deployable, offline supervisory analytics capability** for periodic SOC submissions. It supports
examiner judgement \u2014 it is not a SOC, SIEM, real-time monitor, central log collector, or automated enforcement
system. Every flag it raises is a prioritisation signal for a human examiner, never proof of misconduct.
""")

    st.markdown("#### Pipeline")
    st.code(
        "CSV / JSON submission -> validation + rejects audit -> normalized local parquet\n"
        "                                              |\n"
        "                  peer benchmarks -> execution-gap / negative-space detectors\n"
        "                                              |\n"
        "                   self-contained flags -> entity risk rank -> JSON / table / explain",
        language="text",
    )

    st.markdown("#### The three signals")
    for key, info in DETECTOR_INFO.items():
        with st.container(border=True):
            top_l, top_r = st.columns([4, 1])
            top_l.markdown(f"**{info['label']}** \u2014 {info['question']}")
            with top_r:
                family_badge(key)
            st.caption(info["method"])

    st.markdown("#### Guarantees")
    st.markdown("""
- **Local and offline.** No runtime network call, cloud identity, SaaS dependency, or hosted model. This dashboard
  itself only ever calls `python -m sat_sa.cli` as a local subprocess and reads the plain files it writes.
- **Streamed, not loaded whole.** Generation, CSV ingestion, and parquet detection all use bounded batches; an
  adaptive controller grows or shrinks batch size and worker count from host RAM/CPU headroom, never from a fixed
  guess.
- **Every reject is kept.** Invalid rows never silently disappear \u2014 they land in `rejects.json` with source, row
  index, raw values, and the validation failure, visible on the **Data health** page.
- **Every flag stands alone.** Detector, entity, rationale, source IDs, measurements, baseline, and generation time
  travel with the flag JSON, which is what powers the **Why this fired** panel on every finding.
""")

    st.markdown("#### What this workbench adds on top")
    st.markdown("""
A handful of conveniences live only in this Streamlit layer, clearly separated from the CLI's own data contract:

- **Runs as cycles.** The CLI has no built-in notion of a recurring assessment cycle; each `runs/<name>/` directory
  here stands in for one periodic submission window, which is what lets **Portfolio**, entity **History**, and
  recurrence badges compare "this cycle" against "last cycle."
- **Disposition log.** An append-only, examiner-attributed record of every reviewed-benign / confirmed-escalate /
  insufficient-evidence decision, stored per run.
- **Review queue.** A small prioritized to-do list, separate from the findings themselves.

Neither of these change what gets flagged \u2014 flags.json, entity_scores.csv, and report.json are always produced
by the real CLI, unmodified.
""")

    st.markdown("#### Validation")
    st.markdown("""
For synthetic runs, ground truth is generated and saved separately from what the detectors see, and `satsa validate`
reports precision/recall/F1 per detector by exact key match. That measures whether the implementation can recover
conditions it deliberately injected \u2014 it does **not** establish real-world supervisory effectiveness. Before
operational use, the documented protocol (06-build-test-and-deployment.md \u00a76) calls for replaying anonymised real
submissions against independent examiner findings and reviewing threshold changes with subject-matter experts.
""")


# ────────────────────────────────────────────────────────────────────────
# Entrypoint & navigation wiring
# ────────────────────────────────────────────────────────────────────────


def main() -> None:
    st.set_page_config(
        page_title="SAT-SA \u2014 Supervisory Analytics",
        page_icon="\U0001F6E1",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    bootstrap_session_state()

    run_page = st.Page(page_run_assessment, title="Run assessment", icon="\u25B6")
    portfolio_page = st.Page(page_portfolio, title="Portfolio", icon="\U0001F9ED", default=True)
    entity_page = st.Page(page_entity_profile, title="Entity profile", icon="\U0001F3E2")
    findings_page = st.Page(page_findings_feed, title="Findings feed", icon="\U0001F6A9")
    peer_page = st.Page(page_peer_benchmarking, title="Peer benchmarking", icon="\U0001F4CA")
    queue_page = st.Page(page_review_queue, title="Review queue", icon="\u2705")
    health_page = st.Page(page_data_health, title="Data health", icon="\U0001FA7A")
    library_page = st.Page(page_detector_library, title="Detector library", icon="\U0001F4DA")
    reports_page = st.Page(page_reports, title="Report center", icon="\U0001F4C4")
    how_page = st.Page(page_how_it_works, title="How it works", icon="\U0001F4A1")

    PAGES.update({
        "run_assessment": run_page,
        "portfolio": portfolio_page,
        "entity_profile": entity_page,
        "findings_feed": findings_page,
        "peer_benchmarking": peer_page,
        "review_queue": queue_page,
        "data_health": health_page,
        "detector_library": library_page,
        "reports": reports_page,
        "how_it_works": how_page,
    })

    render_sidebar()

    nav = st.navigation({
        "Assess": [run_page, portfolio_page],
        "Analyse": [entity_page, findings_page, peer_page, queue_page],
        "Audit": [health_page, library_page, reports_page],
        "Reference": [how_page],
    })
    nav.run()


if __name__ == "__main__":
    main()