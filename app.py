"""
SAT-SA — Supervisory Analytics Tool for SOC Assessment
Streamlit supervisor workbench (single-file `app.py`)
=====================================================

What this is
------------
A local, offline *presentation layer* for the SAT-SA CLI. It never duplicates
analytics: every computation goes through the real CLI

    python -m sat_sa.cli <command>        (or the `satsa` console script)

using argument lists (no shell interpolation), and every screen reads the
CLI's own artifacts:

    runs/<run>/source/       synthetic submission, or the 5 uploaded CSVs
    runs/<run>/normalized/   *.parquet (Snappy) + rejects.json
    runs/<run>/results/      flags.json, alert_volumes.json, entity_scores.csv,
                             report.json, validation.txt, review_queue.json,
                             dispositions.jsonl

Page model (SAT-SA_supervisor_UI_spec.md): Portfolio · Entity profile ·
Findings feed · Finding detail (st.dialog) · Peer benchmarking · Review queue ·
Data health · Detector library · Report center, plus Run assessment and
How it works.  One "cycle" == one isolated run directory under ./runs.

Run it
------
    pip install "streamlit>=1.36" pandas pyarrow     # plotly / pyyaml / weasyprint optional
    pip install -e .                                  # the sat_sa package, same venv
    streamlit run app.py

Deep links:  ?page=findings&run=<name>&entity=CSE-003&finding=fg_00012
"""

from __future__ import annotations

import datetime as dt
import html as _html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from functools import partial
from pathlib import Path

import pandas as pd
import streamlit as st
from sat_sa.detectors import DETECTOR_REGISTRY, GROUP_DETECTORS

try:
    import pyarrow.parquet as pq
    PYARROW = True
except Exception:  # pragma: no cover
    PYARROW = False

try:
    import plotly.graph_objects as plotly_go
    PLOTLY = True
except Exception:
    PLOTLY = False

try:
    import altair as alt
    ALTAIR = True
except Exception:
    ALTAIR = False

try:
    import yaml
    YAML_OK = True
except Exception:
    YAML_OK = False

# ----------------------------------------------------------------------------- page config
st.set_page_config(
    page_title="SAT-SA supervisor workbench",
    layout="wide",
    initial_sidebar_state="expanded",
)

ss = st.session_state

# ----------------------------------------------------------------------------- constants
APP_DIR = Path(__file__).resolve().parent
RUNS_DIR = APP_DIR / "runs"
RUN_TABLES = ["entities", "assets", "alerts", "cases", "escalations"]
CLI_COMMAND_OPTIONS = {
    "generate-synth": frozenset({
        "--entities", "--alerts-per-entity", "--seed", "--anomaly-rate",
        "--batch-size", "--adaptive", "--no-adaptive", "--healthcheck-interval", "--out",
    }),
    "ingest": frozenset({
        "--input", "--format", "--batch-size", "--workers", "--adaptive",
        "--no-adaptive", "--healthcheck-interval", "--out",
    }),
    "detect": frozenset({
        "--data", "--detectors", "--config", "--batch-size", "--workers",
        "--adaptive", "--no-adaptive", "--healthcheck-interval", "--out",
    }),
    "system-info": frozenset({"--batch-size", "--workers"}),
    "score": frozenset({"--flags", "--out", "--config"}),
    "report": frozenset({"--scores", "--flags", "--format", "--out"}),
    "explain": frozenset({"--entity-id", "--flags"}),
    "validate": frozenset({"--flags", "--synth-ground-truth"}),
}
SCORE_COLS = ["entity_id", "risk_score", "priority_rank", "flag_count_by_detector",
              "distinct_detectors_triggered", "alert_volume"]

REQUIRED_COLS = {
    "entities": ["entity_id", "name", "peer_group"],
    "assets": ["asset_id", "entity_id", "criticality"],
    "alerts": ["alert_id", "entity_id", "category", "severity", "created_at",
               "disposition", "escalated"],
    "cases": ["case_id", "entity_id", "opened_at", "alert_ids", "root_cause_documented"],
    "escalations": ["escalation_id", "alert_id", "escalated_at", "escalated_to_tier"],
}

PAGES = {
    "run": "Run assessment",
    "portfolio": "Portfolio overview",
    "entity": "Entity profile",
    "findings": "Findings feed",
    "benchmark": "Peer benchmarking",
    "queue": "Review queue",
    "health": "Data health",
    "detectors": "Rules in effect",
    "reports": "Report center",
    "how": "How it works",
}

FAMILY = {key: meta["family"] for key, meta in DETECTOR_REGISTRY.items()}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_COLOR = {"critical": "#922b21", "high": "#b9770e", "medium": "#9a7d0a", "low": "#1e8449"}
FAM_COLOR = {"EG": "#21618c", "NS": "#6c3483"}
DISP_OPTIONS = ["Reviewed – benign", "Confirmed – escalate", "Insufficient evidence"]

DEFAULT_DETECTOR_CONFIG = {
    "fast_closure_k": 1.5,
    "coverage_window_days": 30,
    "coverage_threshold_pct": 0.25,
    "investigation_duration_k": 1.5,
    "low_entity_activity_pct": 0.25,
    "recurrence_min_alerts": 3,
    "workload_deviation_pct": 0.5,
    "min_peer_sample": 4,
    "weights": {key: meta["weight"] for key, meta in DETECTOR_REGISTRY.items()},
}

LEGACY_RULE_META = {
    "fast_closure": dict(
        rule="D1 · fast_closure",
        name="Unusually fast closure of high/critical alerts",
        desc="High/critical severity alerts closed extraordinarily quickly versus this "
             "submission's closure distribution for that severity.",
        method="Statistical outlier — severity-specific Q1 − 1.5 × IQR lower fence",
        threshold="time_to_close < Q1(severity) − 1.5 × IQR(severity)",
        capability="Investigation", family="EG", weight=2,
    ),
    "no_escalation": dict(
        rule="D2 · no_escalation",
        name="Critical true-positive closed without escalation",
        desc="Deterministic process/control inconsistency: critical severity, true positive, "
             "no recorded escalation.",
        method="Deterministic rule (no statistical baseline)",
        threshold="severity=critical ∧ disposition=true_positive ∧ escalated=false",
        capability="Escalation", family="EG", weight=3,
    ),
    "low_coverage": dict(
        rule="D3 · low_coverage",
        name="Low critical-asset coverage vs peers",
        desc="Critical asset generating unusually few alerts versus the peer-group median for "
             "critical assets (possible monitoring blind spot).",
        method="Peer cohort comparison — 30-day observed count vs cohort median",
        threshold="observed_count < 25% × peer median (30-day window)",
        capability="Detection", family="NS", weight=2,
    ),
}

CAPABILITIES = ["Detection", "Investigation", "Escalation", "Incident response",
                "Security operations", "Governance & oversight", "Operational discipline",
                "Cyber resilience"]

PRESETS = {
    "Default — live presentation (8 CSEs · 8,000 alerts)": (8, 1000),
    "Medium — departmental assessment (20 CSEs · 200,000 alerts)": (20, 10000),
    "Large — scalability demonstration (40 CSEs · 2,000,000 alerts)": (40, 50000),
    "Gigantic — capacity rehearsal (100 CSEs · 10,000,000 alerts)": (100, 100000),
}

BM_METRICS = {
    "alert_volume": "Alert volume",
    "risk_score": "Risk score",
    "escalation_rate": "Escalation rate",
    "ack_rate": "Acknowledgement rate",
    "closure_rate": "Closure rate",
    "avg_case_closure_hrs": "Avg case closure (h)",
}

# Detector metadata is shared with the CLI; retain the legacy table above only
# as a compatibility fallback for older cached/UI states.
RULE_META = {**LEGACY_RULE_META, **DETECTOR_REGISTRY}

BM_METRIC_GUIDE = {
    "alert_volume": {
        "definition": "Number of alerts attributed to each entity in this assessment cycle.",
        "read": "Lower is not automatically better; compare entities with similar operating scope.",
        "unit": "alerts",
    },
    "risk_score": {
        "definition": "Composite supervisory risk score produced by the scoring pipeline.",
        "read": "Higher means greater supervisory risk and deserves closer review.",
        "unit": "score",
    },
    "escalation_rate": {
        "definition": "Share of alerts that were escalated (shown as a proportion).",
        "read": "A large difference from peers is a prompt to investigate process and severity mix.",
        "unit": "percent",
    },
    "ack_rate": {
        "definition": "Share of alerts with a recorded first acknowledgement.",
        "read": "Higher generally indicates more alerts were acknowledged; interpret with workload and SLA context.",
        "unit": "percent",
    },
    "closure_rate": {
        "definition": "Share of alerts that have a recorded closure.",
        "read": "Higher means more alerts are closed in this cycle; it does not measure closure quality.",
        "unit": "percent",
    },
    "avg_case_closure_hrs": {
        "definition": "Average elapsed time, in hours, for cases that have been closed.",
        "read": "Lower is faster, but unusually fast closure can warrant investigation when quality controls are weak.",
        "unit": "hours",
    },
}

# version gate ---------------------------------------------------------------
try:
    from packaging.version import Version
    _VER_OK = Version(st.__version__.split("+")[0]) >= Version("1.36")
except Exception:
    _VER_OK = True
if not _VER_OK:
    st.error("This app needs Streamlit ≥ 1.36 (st.dialog, row selection, query params). "
             "Run:  pip install -U streamlit")
    st.stop()

# ----------------------------------------------------------------------------- small utils
def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sanitize_run_name(name: str) -> str:
    """A–Z a–z 0–9 _ - , max 64 chars (filesystem safety, spec §55)."""
    s = re.sub(r"[^A-Za-z0-9_-]", "_", (name or "").strip())
    return s[:64] or "run"


def esc(x) -> str:
    return _html.escape(str(x))


def pill(text, color) -> str:
    return (f'<span style="background:{color};color:#ffffff;padding:2px 10px;'
            f'border-radius:11px;font-size:0.78em;font-weight:600;white-space:nowrap;">'
            f'{esc(text)}</span>')


def fmt_minutes(m):
    try:
        m = float(m)
    except (TypeError, ValueError):
        return "—"
    if pd.isna(m):
        return "—"
    if m < 60:
        return f"{int(round(m))}m"
    return f"{m / 60:.1f}h"


def fmt_int(x) -> str:
    try:
        return f"{int(x):,}"
    except (TypeError, ValueError):
        return "—"


def fmt_pct(x) -> str:
    try:
        return f"{100 * float(x):.0f}%"
    except (TypeError, ValueError):
        return "—"


def severity_label(value) -> str:
    return str(value)


def family_label(value) -> str:
    return str(value)


def disposition_label(value) -> str:
    return str(value)


def show_table(df, **kw):
    """st.dataframe wrapper tolerant to the use_container_width → width migration."""
    try:
        return st.dataframe(df, width="stretch", **kw)
    except TypeError:
        return st.dataframe(df, use_container_width=True, **kw)


def _st_chart(fn, fig):
    try:
        fn(fig, width="stretch")
    except TypeError:
        fn(fig, use_container_width=True)


def bar_chart(data):
    _st_chart(st.bar_chart, data)


def line_chart(data):
    _st_chart(st.line_chart, data)


def styler_map(styler, fn, subset=None):
    if hasattr(styler, "map"):
        return styler.map(fn) if subset is None else styler.map(fn, subset=subset)
    return styler.applymap(fn) if subset is None else styler.applymap(fn, subset=subset)


def _read_json(p: Path, default):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return default


def effective_detector_config(config_path: Path | None) -> tuple[dict, str]:
    """Resolve the detector settings using the same defaults as the CLI."""
    config = {
        **DEFAULT_DETECTOR_CONFIG,
        "weights": dict(DEFAULT_DETECTOR_CONFIG["weights"]),
    }
    source = "built-in defaults (no config file)"
    if config_path and config_path.exists() and YAML_OK:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        config.update({key: loaded[key] for key in DEFAULT_DETECTOR_CONFIG
                       if key != "weights" and key in loaded})
        config["weights"].update(loaded.get("weights") or {})
        source = str(config_path)
    return config, source


# ----------------------------------------------------------------------------- CLI bridge
@st.cache_resource
def _detect_cli():
    """Find a working SAT-SA CLI base command (console script first, module fallback)."""
    candidates = []
    local_console = Path(sys.executable).with_name("satsa.exe" if os.name == "nt" else "satsa")
    if local_console.exists():
        candidates.append([str(local_console)])
    exe = shutil.which("satsa")
    if exe and [exe] not in candidates:
        candidates.append([exe])
    candidates.append([sys.executable, "-m", "sat_sa.cli"])
    for c in candidates:
        try:
            r = subprocess.run(c + ["--help"], capture_output=True, text=True, timeout=120)
            outp = (r.stdout or "") + (r.stderr or "")
            if r.returncode == 0 and ("generate-synth" in outp or "Usage" in outp):
                return c
        except Exception:
            pass
    return None


def run_cli(args) -> dict:
    """Run the CLI with an argument list (never shell interpolation)."""
    base = _detect_cli()
    if base is None:
        return dict(ok=False, returncode=127, elapsed=0.0, cmd=[],
                    output="SAT-SA CLI not found. Install the sat_sa package in this venv "
                           "(pip install -e .) or make the `satsa` command available.")
    cmd = base + [str(a) for a in args]
    command = str(args[0]) if args else ""
    supported = _cli_options(command)
    passed = {part for part in cmd[len(base) + 1:] if part.startswith("--")}
    unsupported = sorted(passed - supported)
    if not supported:
        return dict(ok=False, returncode=2, elapsed=0.0, cmd=cmd,
                    output=f"Could not read help for SAT-SA command: {command!r}.")
    if unsupported:
        return dict(ok=False, returncode=2, elapsed=0.0, cmd=cmd,
                    output=("The Streamlit command builder rejected unsupported CLI option(s): "
                            + ", ".join(unsupported) + "."))
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        out = r.stdout or ""
        if r.stderr:
            out += "\n[stderr]\n" + r.stderr
        return dict(ok=(r.returncode == 0), returncode=r.returncode, output=out,
                    elapsed=time.time() - t0, cmd=cmd)
    except Exception as e:
        return dict(ok=False, returncode=-1, output=f"Subprocess error: {e}",
                    elapsed=time.time() - t0, cmd=cmd)


def _cli_options(command: str) -> frozenset[str]:
    """Return the option contract transcribed from the SAT-SA CLI --help output."""
    return CLI_COMMAND_OPTIONS.get(command, frozenset())


# ----------------------------------------------------------------------------- runs
def list_runs() -> list[dict]:
    out = []
    if RUNS_DIR.exists():
        for d in RUNS_DIR.iterdir():
            if not d.is_dir():
                continue
            has = any((d / p).exists() for p in
                      ["meta.json", "source", "normalized", "results/flags.json"])
            if not has:
                continue
            meta = _read_json(d / "meta.json", {})
            created = meta.get("created") or dt.datetime.fromtimestamp(
                d.stat().st_mtime).isoformat()
            out.append(dict(name=d.name, dir=str(d), created=str(created),
                            mode=str(meta.get("mode", "—")), meta=meta))
    out.sort(key=lambda r: r["created"], reverse=True)
    return out


def art(run_dir: str) -> dict:
    rd = Path(run_dir)
    return dict(
        source=rd / "source", normalized=rd / "normalized", results=rd / "results",
        flags=rd / "results" / "flags.json", scores=rd / "results" / "entity_scores.csv",
        report=rd / "results" / "report.json", volumes=rd / "results" / "alert_volumes.json",
        rejects=rd / "normalized" / "rejects.json",
        gt=rd / "source" / "ground_truth.parquet",
        validation=rd / "results" / "validation.txt",
    )


def current_run_dir():
    runs = list_runs()
    if not runs:
        return None
    for r in runs:
        if r["name"] == ss.get("active_run"):
            return r["dir"]
    ss.active_run = runs[0]["name"]
    return runs[0]["dir"]


def run_status_line(name: str) -> str:
    rd = RUNS_DIR / name
    if not rd.exists():
        return "○ new"
    a = art(str(rd))
    bits = []
    for lbl, p in [("source", a["source"]), ("normalized", a["normalized"]),
                   ("flags", a["flags"]), ("scores", a["scores"]), ("report", a["report"])]:
        bits.append(("present: " if p.exists() else "missing: ") + lbl)
    return " · ".join(bits)


def parquet_rows(p: Path):
    if not (p.exists() and PYARROW):
        return None
    try:
        return pq.read_metadata(str(p)).num_rows
    except Exception:
        return None


# ----------------------------------------------------------------------------- cached loaders
@st.cache_data
def load_meta(run_dir: str) -> dict:
    return _read_json(Path(run_dir) / "meta.json", {})


@st.cache_data
def load_flags(run_dir: str) -> list:
    return _read_json(art(run_dir)["flags"], [])


@st.cache_data
def load_scores(run_dir: str) -> pd.DataFrame:
    p = art(run_dir)["scores"]
    empty = pd.DataFrame(columns=SCORE_COLS + ["_counts"])
    if not p.exists():
        return empty
    try:
        df = pd.read_csv(p)
    except Exception:
        return empty
    for c in SCORE_COLS:
        if c not in df.columns:
            df[c] = "{}" if c == "flag_count_by_detector" else 0
    counts = []
    for v in df["flag_count_by_detector"]:
        try:
            d = json.loads(v) if isinstance(v, str) else (v or {})
        except Exception:
            d = {}
        counts.append(d if isinstance(d, dict) else {})
    df["_counts"] = counts
    return df


@st.cache_data
def load_volumes(run_dir: str) -> dict:
    return _read_json(art(run_dir)["volumes"], {})


@st.cache_data
def load_entities(run_dir: str) -> pd.DataFrame:
    p = Path(run_dir) / "normalized" / "entities.parquet"
    if not (p.exists() and PYARROW):
        return pd.DataFrame(columns=["entity_id", "name", "peer_group", "sector"])
    try:
        df = pq.read_table(str(p), columns=["entity_id", "name", "peer_group", "sector"]).to_pandas()
    except Exception:
        df = pq.read_table(str(p)).to_pandas()
    return df


@st.cache_data
def load_assets(run_dir: str) -> pd.DataFrame:
    p = Path(run_dir) / "normalized" / "assets.parquet"
    if not (p.exists() and PYARROW):
        return pd.DataFrame()
    try:
        return pq.read_table(str(p)).to_pandas()
    except Exception:
        return pd.DataFrame()


def _coerce_datetime_columns(df: pd.DataFrame, columns) -> pd.DataFrame:
    """Normalize timestamp columns so date arithmetic works across Parquet schemas."""
    for column in columns:
        if column in df.columns:
            df[column] = pd.to_datetime(df[column], errors="coerce", utc=True)
    return df


@st.cache_data
def load_rejects(run_dir: str) -> list:
    return _read_json(art(run_dir)["rejects"], [])


@st.cache_data
def load_entity_alerts(run_dir: str, entity_id: str) -> pd.DataFrame:
    p = Path(run_dir) / "normalized" / "alerts.parquet"
    if not (p.exists() and PYARROW):
        return pd.DataFrame()
    try:
        df = pq.read_table(str(p), filters=[("entity_id", "==", entity_id)]).to_pandas()
        return _coerce_datetime_columns(df, ["created_at", "first_ack_at", "closed_at"])
    except Exception:
        return pd.DataFrame()


@st.cache_data
def load_entity_cases(run_dir: str, entity_id: str) -> pd.DataFrame:
    p = Path(run_dir) / "normalized" / "cases.parquet"
    if not (p.exists() and PYARROW):
        return pd.DataFrame()
    try:
        df = pq.read_table(str(p), filters=[("entity_id", "==", entity_id)]).to_pandas()
        return _coerce_datetime_columns(df, ["opened_at", "closed_at"])
    except Exception:
        return pd.DataFrame()


@st.cache_data
def alert_aggregates(run_dir: str) -> pd.DataFrame:
    """Bounded scan of alerts.parquet (row-group batches) → per-entity counters.
    Mirrors the CLI's streaming contract: never loads the full alert set."""
    path = Path(run_dir) / "normalized" / "alerts.parquet"
    if not (path.exists() and PYARROW):
        return pd.DataFrame()
    acc: dict[str, dict] = {}
    try:
        pf = pq.ParquetFile(str(path))
        cols = [c for c in ["entity_id", "created_at", "first_ack_at", "closed_at",
                            "escalated", "disposition"] if c in pf.schema_arrow.names]
        for batch in pf.iter_batches(batch_size=250_000, columns=cols):
            if batch.num_rows == 0:
                continue
            b = batch.to_pandas()
            _coerce_datetime_columns(b, ["created_at", "first_ack_at", "closed_at"])
            e = b["entity_id"].astype(str)
            for eid, n in e.value_counts().items():
                a = acc.setdefault(str(eid), {})
                a["alerts"] = a.get("alerts", 0) + int(n)
            if "closed_at" in b and "created_at" in b:
                m = b["closed_at"].notna()
                if m.any():
                    dur = (b.loc[m, "closed_at"] - b.loc[m, "created_at"]).dt.total_seconds() / 60.0
                    dur = dur.clip(lower=0)
                    for eid, s in dur.groupby(e[m]).sum().items():
                        a = acc.setdefault(str(eid), {})
                        a["closure_min"] = a.get("closure_min", 0.0) + float(s)
                    for eid, n in e[m].value_counts().items():
                        a = acc.setdefault(str(eid), {})
                        a["closed"] = a.get("closed", 0) + int(n)
            if "first_ack_at" in b:
                m = b["first_ack_at"].notna()
                if m.any():
                    for eid, n in e[m].value_counts().items():
                        a = acc.setdefault(str(eid), {})
                        a["acked"] = a.get("acked", 0) + int(n)
            if "escalated" in b:
                esc_col = b["escalated"]
                if esc_col.dtype == bool:
                    m = esc_col
                else:
                    m = esc_col.astype(str).str.lower().isin(["true", "1"])
                if m.any():
                    for eid, n in e[m].value_counts().items():
                        a = acc.setdefault(str(eid), {})
                        a["escalated"] = a.get("escalated", 0) + int(n)
            if "disposition" in b:
                for val, field in (("unresolved", "unresolved"), ("true_positive", "true_positive")):
                    m = b["disposition"] == val
                    if m.any():
                        for eid, n in e[m].value_counts().items():
                            a = acc.setdefault(str(eid), {})
                            a[field] = a.get(field, 0) + int(n)
    except Exception:
        return pd.DataFrame()
    rows = []
    for eid, a in acc.items():
        n = a.get("alerts", 0)
        closed = a.get("closed", 0)
        rows.append(dict(
            entity_id=eid, alerts=n, closed=closed, acked=a.get("acked", 0),
            escalated=a.get("escalated", 0), unresolved=a.get("unresolved", 0),
            true_positive=a.get("true_positive", 0),
            avg_closure_min=(a.get("closure_min", 0.0) / closed) if closed else None,
            closure_rate=closed / n if n else None,
            ack_rate=a.get("acked", 0) / n if n else None,
            escalation_rate=a.get("escalated", 0) / n if n else None,
        ))
    return pd.DataFrame(rows)


@st.cache_data
def case_aggregates(run_dir: str) -> pd.DataFrame:
    p = Path(run_dir) / "normalized" / "cases.parquet"
    if not (p.exists() and PYARROW):
        return pd.DataFrame()
    try:
        df = pq.read_table(str(p), columns=["entity_id", "opened_at", "closed_at"]).to_pandas()
    except Exception:
        return pd.DataFrame()
    df = _coerce_datetime_columns(df, ["opened_at", "closed_at"])
    if df.empty:
        return pd.DataFrame()
    closed = df["closed_at"].notna()
    df["_hrs"] = None
    df.loc[closed, "_hrs"] = (df.loc[closed, "closed_at"] - df.loc[closed, "opened_at"]).dt.total_seconds() / 3600.0
    g = df.groupby("entity_id")
    out = pd.DataFrame(dict(
        entity_id=g.size().index, n_cases=g.size().values,
        closed_cases=g.apply(lambda x: int(x["closed_at"].notna().sum()), include_groups=False).values,
        avg_case_closure_hrs=g["_hrs"].mean().values,
    ))
    return out.reset_index(drop=True)


@st.cache_data
def entity_names(run_dir: str) -> dict:
    ent = load_entities(run_dir)
    if ent.empty:
        return {}
    names = ent["name"] if "name" in ent.columns else ent["entity_id"]
    return dict(zip(ent["entity_id"].astype(str), names.astype(str)))


@st.cache_data
def entity_metrics(run_dir: str) -> pd.DataFrame:
    ent = load_entities(run_dir)
    agg = alert_aggregates(run_dir)
    cases = case_aggregates(run_dir)
    scores = load_scores(run_dir)
    vol = load_volumes(run_dir)
    names = entity_names(run_dir)
    ids: list[str] = []
    if not ent.empty:
        ids += [str(x) for x in ent["entity_id"]]
    if not scores.empty:
        ids += [str(x) for x in scores["entity_id"]]
    if not agg.empty:
        ids += [str(x) for x in agg["entity_id"]]
    universe = list(dict.fromkeys(ids))
    emap = ent.set_index("entity_id") if not ent.empty else None
    amap = agg.set_index("entity_id") if not agg.empty else None
    cmap = cases.set_index("entity_id") if not cases.empty else None
    smap = scores.set_index("entity_id") if not scores.empty else None
    flags = load_flags(run_dir)
    fcounts = pd.Series([f.get("entity_id") for f in flags]).value_counts().to_dict()

    def _g(dfidx, col, e, default=None):
        if dfidx is None or e not in dfidx.index or col not in dfidx.columns:
            return default
        v = dfidx.at[e, col]
        return default if pd.isna(v) else v

    rows = []
    for e in universe:
        vol_e = vol.get(e)
        if vol_e is None:
            vol_e = _g(smap, "alert_volume", e, 0) or _g(amap, "alerts", e, 0)
        rows.append(dict(
            entity_id=e, entity=names.get(e, e),
            peer_group=_g(emap, "peer_group", e, "—"),
            sector=_g(emap, "sector", e, "—"),
            alert_volume=int(vol_e or 0),
            risk_score=_g(smap, "risk_score", e, 0.0),
            escalation_rate=_g(amap, "escalation_rate", e, None),
            ack_rate=_g(amap, "ack_rate", e, None),
            closure_rate=_g(amap, "closure_rate", e, None),
            avg_case_closure_hrs=_g(cmap, "avg_case_closure_hrs", e, None),
            flag_count=int(fcounts.get(e, 0)),
        ))
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- findings logic
def finding_key(f: dict) -> tuple:
    det = f.get("detector")
    ev = f.get("evidence") or {}
    if det == "low_coverage":
        aid = ev.get("asset_id")
        if not aid:
            aids = ev.get("asset_ids") or []
            aid = aids[0] if isinstance(aids, list) and aids else None
        return ("asset", str(aid))
    aids = ev.get("alert_ids") or []
    if isinstance(aids, str):
        aids = [aids]
    return ("alert", str(aids[0]) if aids else str(f.get("flag_id")))


def finding_severity(f: dict) -> str:
    det = f.get("detector")
    ev = f.get("evidence") or {}
    if det == "no_escalation":
        return "critical"
    if det == "fast_closure":
        try:
            q1, obs = float(ev.get("baseline_q1_minutes")), float(ev.get("time_to_close_minutes"))
            factor = q1 / max(obs, 0.01)
            if factor >= 8:
                return "critical"
            if factor >= 3:
                return "high"
        except (TypeError, ValueError):
            pass
        return "medium"
    if det == "low_coverage":
        try:
            obs, med = float(ev.get("observed_count")), float(ev.get("peer_median"))
            if obs == 0:
                return "high"
            return "high" if (med and obs / med < 0.1) else "medium"
        except (TypeError, ValueError):
            pass
        return "medium"
    return "medium"


def why_line(f: dict) -> str:
    det = f.get("detector")
    ev = f.get("evidence") or {}
    try:
        if det == "fast_closure":
            obs = float(ev.get("time_to_close_minutes"))
            q1 = float(ev.get("baseline_q1_minutes"))
            iqr = float(ev.get("baseline_iqr_minutes"))
            return (f"closure {fmt_minutes(obs)} vs severity baseline Q1 {fmt_minutes(q1)}, "
                    f"IQR {fmt_minutes(iqr)} → lower fence {fmt_minutes(q1 - 1.5 * iqr)}")
        if det == "low_coverage":
            return (f"observed {ev.get('observed_count')} alerts vs peer median "
                    f"{ev.get('peer_median')} over {ev.get('window_days', 30)}d "
                    f"(threshold 25% of median)")
    except (TypeError, ValueError):
        pass
    if det == "no_escalation":
        return "severity=critical ∧ disposition=true_positive ∧ escalated=false (deterministic)"
    return RULE_META.get(det, {}).get("threshold", "")


@st.cache_data
def build_findings(run_dir: str) -> pd.DataFrame:
    flags = load_flags(run_dir)
    rows = []
    for f in flags:
        ev = f.get("evidence") or {}
        det = str(f.get("detector", ""))
        aids = ev.get("alert_ids") or []
        if isinstance(aids, str):
            aids = [aids]
        asset_id = ev.get("asset_id")
        if not asset_id:
            aids2 = ev.get("asset_ids") or []
            asset_id = aids2[0] if isinstance(aids2, list) and aids2 else None
        rows.append(dict(
            finding_id=f.get("flag_id"), entity_id=f.get("entity_id"),
            family=FAMILY.get(det, "?"), detector=det,
            rule=RULE_META.get(det, {}).get("rule", det),
            capability=RULE_META.get(det, {}).get("capability", ""),
            severity=finding_severity(f),
            confidence=("det" if det == "no_escalation" else "stat"),
            detected_at=str(f.get("generated_at", "")),
            rationale=str(f.get("rationale", "")),
            ref=", ".join(map(str, aids)) if aids else (str(asset_id) if asset_id else ""),
            key=finding_key(f), _flag=f,
        ))
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("finding_id").reset_index(drop=True)
    return df


@st.cache_data
def prior_flag_keys(run_dir: str) -> frozenset:
    return frozenset((str(f.get("entity_id")),) + finding_key(f) for f in load_flags(run_dir))


@st.cache_data
def prior_flag_entities(run_dir: str) -> frozenset:
    return frozenset(str(f.get("entity_id")) for f in load_flags(run_dir))


def findings_view(run_dir: str) -> pd.DataFrame:
    df = build_findings(run_dir)
    if df.empty:
        return df
    ent = load_entities(run_dir)
    names = entity_names(run_dir)
    sectors = (dict(zip(ent["entity_id"].astype(str), ent["sector"].astype(str)))
               if not ent.empty and "sector" in ent.columns else {})
    df["entity"] = df["entity_id"].astype(str).map(lambda e: names.get(e, e))
    df["sector"] = df["entity_id"].astype(str).map(lambda e: sectors.get(e, "—"))
    prior = prior_run(Path(run_dir).name)
    if prior:
        keys = prior_flag_keys(prior["dir"])
        df["recurring"] = [(e, *k) in keys for e, k in zip(df["entity_id"].astype(str), df["key"])]
    else:
        df["recurring"] = False
    df["disposition"] = df["finding_id"].map(latest_dispositions(run_dir)).fillna("—")
    return df


# ----------------------------------------------------------------------------- dispositions & queue
def disp_path(run_dir: str) -> Path:
    return Path(run_dir) / "results" / "dispositions.jsonl"


def load_dispositions(run_dir: str) -> list:
    p = disp_path(run_dir)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def latest_dispositions(run_dir: str) -> dict:
    d = {}
    for e in load_dispositions(run_dir):  # append-only file: later entries win
        d[e.get("finding_id")] = e.get("disposition")
    return d


def append_disposition(run_dir: str, entry: dict):
    p = disp_path(run_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def queue_path(run_dir: str) -> Path:
    return Path(run_dir) / "results" / "review_queue.json"


def load_queue(run_dir: str) -> list:
    return _read_json(queue_path(run_dir), [])


def save_queue(run_dir: str, items: list):
    p = queue_path(run_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _queue_priority(sev: str, risk: float, recurring: bool = False) -> float:
    sev_w = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}
    p = sev_w.get(sev, 1.0) * (1.5 if recurring else 1.0) + float(risk or 0) / 5.0
    return round(p, 2)


def add_finding_to_queue(run_dir: str, f: dict, recurring: bool = False) -> tuple[bool, str]:
    fid = f.get("flag_id")
    items = load_queue(run_dir)
    if any(it.get("id") == fid for it in items):
        return False, f"{fid} is already in the review queue."
    sev = finding_severity(f)
    scores = load_scores(run_dir)
    risk = 0.0
    if not scores.empty:
        s = scores[scores["entity_id"] == f.get("entity_id")]
        if len(s):
            risk = float(s.iloc[0]["risk_score"])
    ev = f.get("evidence") or {}
    aids = ev.get("alert_ids") or []
    ref = ", ".join(map(str, aids)) if aids else str(ev.get("asset_id") or "")
    items.append(dict(
        id=fid, finding_id=fid, entity_id=f.get("entity_id"),
        reason=(f.get("rationale") or "")[:160], severity=sev, ref=ref,
        priority=_queue_priority(sev, risk, recurring),
        status="To review", assignee="", added_at=now_iso(),
    ))
    save_queue(run_dir, items)
    return True, f"{fid} added to the review queue."


def _queue_field_cb(run_dir: str, item_id: str, field: str, key: str):
    items = load_queue(run_dir)
    for it in items:
        if it.get("id") == item_id:
            it[field] = ss[key]
    save_queue(run_dir, items)


# ----------------------------------------------------------------------------- cycle history
@st.cache_data
def cycle_history(sig: tuple) -> pd.DataFrame:
    rows = []
    asc = list(reversed(sig))  # oldest first
    for i, (name, created, d) in enumerate(asc):
        sc = load_scores(d)
        fl = load_flags(d)
        vol = load_volumes(d)
        fcounts = pd.Series([f.get("entity_id") for f in fl]).value_counts().to_dict()
        risk_map = dict(zip(sc["entity_id"].astype(str), sc["risk_score"])) if not sc.empty else {}
        for e in set(risk_map) | set(vol) | set(fcounts):
            rows.append(dict(
                cycle_order=i, cycle=name, created=created, entity_id=str(e),
                risk_score=float(risk_map.get(e, 0.0)),
                alert_volume=int(vol.get(e, 0)),
                flag_count=int(fcounts.get(e, 0)),
            ))
    return pd.DataFrame(rows)


def _history_df() -> pd.DataFrame:
    sig = tuple((r["name"], r["created"], r["dir"]) for r in list_runs())
    if not sig:
        return pd.DataFrame()
    return cycle_history(sig)


def prior_run(active_name: str):
    runs = list_runs()  # newest first
    names = [r["name"] for r in runs]
    if active_name in names:
        i = names.index(active_name)
        if i + 1 < len(runs):
            return runs[i + 1]
    return None


def _finding_cycles(entity_id: str, key: tuple) -> list[str]:
    out = []
    for r in list_runs():
        for f in load_flags(r["dir"]):
            if str(f.get("entity_id")) == str(entity_id) and finding_key(f) == key:
                out.append(r["name"])
                break
    return out


# ----------------------------------------------------------------------------- navigation
def sync_params():
    try:
        p = st.query_params
        p["page"] = ss.nav_page
        for k, v in (("entity", ss.get("active_entity_id")),
                     ("finding", ss.get("open_finding_id")),
                     ("run", ss.get("active_run"))):
            if v:
                p[k] = str(v)
            elif k in p:
                del p[k]
    except Exception:
        pass


def _qp_del(k: str):
    try:
        if k in st.query_params:
            del st.query_params[k]
    except Exception:
        pass


def go(page: str, entity=None, finding=None, push=True):
    if push:
        h = (ss.get("nav_history") or [])[-11:]
        if ss.nav_page != page or entity is not None:
            h.append(dict(page=ss.nav_page, entity=ss.get("active_entity_id"),
                          finding=ss.get("open_finding_id")))
        ss.nav_history = h
    ss.nav_page = page
    if entity is not None:
        ss.active_entity_id = entity
    if finding is not None:
        ss.open_finding_id = finding
    sync_params()
    st.rerun()


def go_back():
    h = ss.get("nav_history") or []
    if h:
        prev = h.pop()
        ss.nav_history = h
        ss.nav_page = prev["page"]
        ss.active_entity_id = prev.get("entity")
        ss.open_finding_id = prev.get("finding")
        sync_params()
        st.rerun()


def open_finding(fid: str, entity=None):
    ss.open_finding_id = fid
    if entity:
        ss.active_entity_id = entity
    sync_params()
    st.rerun()


def maybe_open_finding(rd):
    fid = ss.get("open_finding_id")
    if not fid:
        return
    ss.open_finding_id = None
    _qp_del("finding")
    if rd is None:
        return
    f = next((x for x in load_flags(str(rd)) if x.get("flag_id") == fid), None)
    if f is None:
        st.warning(f"Finding {fid} not found in cycle “{ss.get('active_run')}”.")
        return
    finding_dialog(f, str(rd))


# ----------------------------------------------------------------------------- session init & deep links
if "nav_page" not in ss:
    ss.nav_page = "portfolio" if list_runs() else "run"
if "nav_history" not in ss:
    ss.nav_history = []
if "active_run" not in ss:
    ss.active_run = None
if "examiner_name" not in ss:
    ss.examiner_name = "Examiner-01"
if "findings_filter" not in ss:
    ss.findings_filter = {}
if "search_results" not in ss:
    ss.search_results = None
if "preset" not in ss:
    ss.preset = next(iter(PRESETS))
for _key, _default in {
    "pf_entities": 8,
    "pf_ape": 1000,
    "pf_anom": 0.15,
    "pf_seed": 42,
    "pf_adaptive": True,
    "pf_batch": 0,
    "pf_workers": 0,
    "pf_hc": 4,
    "pf_cfg": "detector_config.yaml",
}.items():
    if _key not in ss:
        ss[_key] = _default

try:
    _p = st.query_params
    if _p.get("run"):
        ss.active_run = _p["run"]
    if _p.get("page") in PAGES:
        ss.nav_page = _p["page"]
    if _p.get("entity"):
        ss.active_entity_id = _p["entity"]
    if _p.get("finding"):
        ss.open_finding_id = _p["finding"]
except Exception:
    pass


# ----------------------------------------------------------------------------- sidebar & search
def _cycle_changed():
    ss.active_run = ss.cycle_select
    ss.active_entity_id = None
    ss.open_finding_id = None
    ss.findings_filter = {}
    sync_params()


def render_sidebar():
    with st.sidebar:
        st.markdown("# Sherlog")
        st.markdown("#### SAT-SA")
        st.caption("Supervisory Analytics Tool — SOC Assessment workbench")
        st.divider()
        runs = list_runs()
        if runs:
            names = [r["name"] for r in runs]
            if ss.get("active_run") not in names:
                ss.active_run = names[0]
            # reset stale widget state (e.g. after a pipeline finished)
            if "cycle_select" in ss and ss.cycle_select != ss.active_run:
                del ss["cycle_select"]
            labels = {r["name"]: f"{r['name']} · {r['mode']} · {r['created'][:10]}" for r in runs}
            st.selectbox("Cycle (submission run)", names, index=names.index(ss.active_run),
                         format_func=lambda n: labels.get(n, n),
                         key="cycle_select", on_change=_cycle_changed)
            st.caption(run_status_line(ss.active_run))
        else:
            st.caption("No assessment runs yet — start at Run assessment.")
        st.divider()
        for pid, label in PAGES.items():
            if st.button(label, key=f"nav_{pid}", use_container_width=True,
                         type="primary" if ss.nav_page == pid else "secondary"):
                go(pid)
        st.divider()
        st.text_input("Search entity / finding ID", key="search", on_change=_do_search,
                      placeholder="CSE-003 · fg_00012")
        st.divider()
        st.text_input("Examiner", key="examiner_name")
        st.caption("Role: NCIIPC supervisor · read-mostly auditor view: Detector library")
        if st.button("Refresh artifacts", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
        st.caption("Flags are prioritisation signals, not proof of misconduct. "
                   "Offline & periodic — no real-time monitoring.")


def _do_search():
    q = (ss.get("search") or "").strip()
    if not q:
        ss.search_results = None
        return
    res = dict(q=q, entities=[], findings=[])
    rd = current_run_dir()
    if rd:
        ent = load_entities(str(rd))
        if not ent.empty:
            for _, r in ent.iterrows():
                eid, nm = str(r.get("entity_id", "")), str(r.get("name", ""))
                if q.lower() in eid.lower() or q.lower() in nm.lower():
                    res["entities"].append((eid, nm))
        for f in load_flags(str(rd)):
            if q.lower() in str(f.get("flag_id", "")).lower():
                res["findings"].append((f.get("flag_id"), f.get("entity_id"),
                                        str(f.get("detector"))))
    ss.search_results = res


def maybe_show_search():
    r = ss.get("search_results")
    if not r:
        return
    with st.container(border=True):
        c, c2 = st.columns([6, 1])
        c.markdown(f"**Search results for “{esc(r['q'])}”** — active cycle "
                   f"{esc(ss.get('active_run') or '—')}")
        if c2.button("Clear", help="Clear results"):
            ss.search_results = None
            st.rerun()
        if r["entities"]:
            st.caption("Entities")
            for eid, nm in r["entities"][:8]:
                if st.button(f"{nm} ({eid})", key=f"sr_e_{eid}"):
                    go("entity", entity=eid)
        if r["findings"]:
            st.caption("Findings")
            for fid, eid, det in r["findings"][:8]:
                if st.button(f"{fid} · {eid} · {det}", key=f"sr_f_{fid}"):
                    open_finding(fid, entity=eid)
        if not r["entities"] and not r["findings"]:
            st.caption("No matches in the active cycle.")


# ----------------------------------------------------------------------------- shared components
def parse_validation(text: str) -> dict:
    out = {}
    for k in ["injected", "detected", "precision", "recall", "f1"]:
        m = re.search(rf"{k}[^0-9.]*([0-9.]+)", text, re.I)
        if m:
            out[k] = float(m.group(1))
    return out


def show_validation_panel(run_dir: str, key_prefix="val"):
    a = art(run_dir)
    if not a["gt"].exists():
        st.caption("Validation against synthetic ground truth is not applicable to uploaded "
                   "submissions — real-world validation must use independent examiner findings.")
        return
    with st.container(border=True):
        st.markdown("**Synthetic ground-truth validation** — CLI `validate` "
                    "(precision / recall / F1 by exact alert/asset key)")
        col = st.columns([1, 3])
        if col[0].button("Run validation", key=f"{key_prefix}_btn"):
            res = run_cli(["validate", "--flags", str(a["flags"]),
                           "--synth-ground-truth", str(a["gt"])])
            if res["ok"]:
                a["validation"].parent.mkdir(parents=True, exist_ok=True)
                a["validation"].write_text(res["output"], encoding="utf-8")
            else:
                st.error(res["output"][-2000:])
        text = a["validation"].read_text(encoding="utf-8") if a["validation"].exists() else ""
        if text:
            m = parse_validation(text)
            if m:
                mcols = st.columns(len(m))
                for c2, (k, v) in zip(mcols, m.items()):
                    c2.metric(k, f"{v:g}")
            with st.expander("CLI output"):
                st.code(text)
        else:
            st.caption("Not run yet for this cycle.")


def render_findings_table(run_dir: str, entity_id=None, family=None, filters=None,
                          key_prefix="ff"):
    """Reusable findings-feed component (spec §3.3) — table + row actions + dialog link."""
    df = findings_view(run_dir)
    if df.empty:
        st.info("No findings in this cycle. Run detection from Run assessment, "
                "or loosen the filters.")
        return
    flt = ss.get("findings_filter") or {}
    b_ent, b_fam, b_det = flt.get("entities"), flt.get("family"), flt.get("detector")
    if b_ent or b_fam or b_det:
        c1, c2 = st.columns([5, 1])
        c1.caption(f"Link filter — entities: {', '.join(b_ent) if b_ent else 'all'} · "
                   f"family: {b_fam or 'all'} · rule: {b_det or 'all'}")
        if c2.button("Clear link filter", key=f"{key_prefix}_clrf"):
            ss.findings_filter = {}
            st.rerun()
    view = df.copy()
    if entity_id:
        view = view[view["entity_id"] == entity_id]
    if family:
        view = view[view["family"] == family]
    if not family and b_fam:
        view = view[view["family"] == b_fam]
    if b_det:
        view = view[view["detector"] == b_det]
    if b_ent:
        view = view[view["entity_id"].isin(b_ent)]
    if filters:
        if filters.get("entities"):
            view = view[view["entity_id"].isin(filters["entities"])]
        if filters.get("sector"):
            view = view[view["sector"].isin(filters["sector"])]
        if filters.get("severity"):
            view = view[view["severity"].isin(filters["severity"])]
        if filters.get("capability"):
            view = view[view["capability"].isin(filters["capability"])]
        if filters.get("detector"):
            view = view[view["detector"].isin(filters["detector"])]
        if filters.get("disposition", "Any") != "Any":
            view = view[view["disposition"] == filters["disposition"]]
    if view.empty:
        st.caption("No findings match the current filters.")
        return
    view = view.assign(_sev=view["severity"].map(SEV_RANK).fillna(9))
    view = view.sort_values(["recurring", "_sev", "finding_id"],
                            ascending=[False, True, True])
    disp = pd.DataFrame({
        "Finding": view["finding_id"],
        "Entity": view["entity"].astype(str) + " (" + view["entity_id"].astype(str) + ")",
        "Family": view["family"].map(family_label),
        "Rule": view["rule"],
        "Capability": view["capability"],
        "Severity": view["severity"].map(severity_label),
        "Conf.": view["confidence"],
        "Detected": view["detected_at"].str.replace("T", " ", regex=False).str[:16],
        "Disposition": view["disposition"].map(disposition_label),
        "Recurs": view["recurring"].map(lambda b: "recurring" if b else ""),
        "Ref": view["ref"],
    })
    st.caption(f"{len(view)} findings · default sort: recurring first, then severity. "
               "Click a row for actions.")
    ev = show_table(disp, hide_index=True, key=f"{key_prefix}_tbl",
                    on_select="rerun", selection_mode="single-row")
    rows = ev.selection.rows if (ev and hasattr(ev, "selection")) else []
    if rows:
        row = view.iloc[rows[0]]
        st.divider()
        c1, c2, c3 = st.columns(3)
        if c1.button("Open finding detail", key=f"{key_prefix}_open", type="primary"):
            open_finding(row["finding_id"], entity=row["entity_id"])
        if c2.button("Add to review queue", key=f"{key_prefix}_queue"):
            ok, msg = add_finding_to_queue(run_dir, row["_flag"], bool(row["recurring"]))
            (st.toast if ok else st.warning)(msg) if ok else st.warning(msg)
            if ok:
                st.toast(msg)
        if c3.button("Open entity profile", key=f"{key_prefix}_ent"):
            go("entity", entity=row["entity_id"])
        with st.expander("Rationale"):
            st.write(row["rationale"])
            st.caption(f"Why this fired: {why_line(row['_flag'])}")


# ----------------------------------------------------------------------------- Run assessment page
def _default_run_name() -> str:
    return f"cycle-{dt.datetime.now().strftime('%Y%m%d-%H%M')}"


def _runtime_options(command: str, batch, workers, adaptive, hc) -> list[tuple[str, object]]:
    """Return only runtime options advertised by the installed command's help."""
    supported = _cli_options(command)
    desired = []
    if batch is not None:
        desired.append(("--batch-size", int(batch)))
    if workers is not None:
        desired.append(("--workers", int(workers)))
    adaptive_flag = "--adaptive" if adaptive else "--no-adaptive"
    desired.append((adaptive_flag, True))
    if hc:
        desired.append(("--healthcheck-interval", int(hc)))
    return [(option, value) for option, value in desired if option in supported]


def _command_args(command: str, options: list[tuple[str, object]]) -> list[str]:
    """Build a command only from options documented by that command's --help."""
    supported = _cli_options(command)
    unsupported = [option for option, value in options
                   if value is not None and option not in supported]
    if unsupported:
        raise ValueError(f"{command} does not support: {', '.join(unsupported)}")
    args = [command]
    for option, value in options:
        if value is None:
            continue
        args.append(option)
        if value is not True:
            args.append(str(value))
    return args


def _stage_uploads(src: Path, uploads: dict) -> dict:
    t0 = time.time()
    try:
        src.mkdir(parents=True, exist_ok=True)
        saved = []
        for stem, fobj in uploads.items():
            (src / f"{stem}.csv").write_bytes(fobj.getvalue())
            saved.append(stem)
        missing = [t for t in RUN_TABLES if t not in uploads]
        msg = f"Staged tables: {', '.join(saved)}"
        if missing:
            msg += f" — MISSING: {', '.join(missing)}"
        return dict(ok=not missing, returncode=0, output=msg,
                    elapsed=time.time() - t0, cmd=[])
    except Exception as e:
        return dict(ok=False, returncode=-1, output=str(e),
                    elapsed=time.time() - t0, cmd=[])


def _write_meta(rd: Path, meta: dict):
    (rd / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _command_output_excerpt(output: str, limit=12_000) -> str:
    """Keep both the command context and the final exception visible in the UI."""
    if len(output) <= limit:
        return output
    head = min(2_000, limit // 3)
    tail = limit - head
    return output[:head] + "\n\n... output truncated; final lines follow ...\n\n" + output[-tail:]


def run_pipeline(name: str, mode: str, params: dict, uploads: dict):
    rd = RUNS_DIR / name
    (rd / "results").mkdir(parents=True, exist_ok=True)
    src, norm, res = rd / "source", rd / "normalized", rd / "results"
    cfgp = (APP_DIR / params["config"]) if params.get("config") else None
    config, config_source = effective_detector_config(cfgp)
    meta = dict(name=name, mode=mode, created=now_iso(), steps=[], params=params,
                effective_detector_config=config,
                detector_config_source=config_source)
    _write_meta(rd, meta)

    synth_rt = _runtime_options("generate-synth", params.get("batch"), params.get("workers"),
                                params.get("adaptive", True), params.get("hc", 4))
    ingest_rt = _runtime_options("ingest", params.get("batch"), params.get("workers"),
                                 params.get("adaptive", True), params.get("hc", 4))
    detect_rt = _runtime_options("detect", params.get("batch"), params.get("workers"),
                                 params.get("adaptive", True), params.get("hc", 4))
    config = str(cfgp) if (cfgp and cfgp.exists()) else None

    try:
        steps = []
        if mode == "upload":
            steps.append(("Stage uploaded submission files", "local", lambda: _stage_uploads(src, uploads)))
        else:
            steps.append(("Generate deterministic synthetic submission", "cli",
                          _command_args("generate-synth", [
                              ("--entities", params["entities"]),
                              ("--alerts-per-entity", params["ape"]),
                              ("--seed", params["seed"]),
                              ("--anomaly-rate", params["anomaly"]),
                              *synth_rt, ("--out", str(src)),
                          ])))
        steps.append(("Ingest & validate (Pydantic v2 → Parquet + rejects.json)", "cli",
                      _command_args("ingest", [
                          ("--input", str(src)), ("--format", "csv"),
                          *ingest_rt, ("--out", str(norm)),
                      ])))
        steps.append(("Detect signals (two-pass Parquet scan · D1 D2 D3)", "cli",
                      _command_args("detect", [
                          ("--data", str(norm)),
                          ("--detectors", "execution_gaps,negative_space"),
                          ("--config", config), *detect_rt,
                          ("--out", str(res / "flags.json")),
                      ])))
        steps.append(("Score & rank entities", "cli",
                      _command_args("score", [
                          ("--flags", str(res / "flags.json")),
                          ("--config", config),
                          ("--out", str(res / "entity_scores.csv")),
                      ])))
        steps.append(("Publish report.json", "cli",
                      _command_args("report", [
                          ("--scores", str(res / "entity_scores.csv")),
                          ("--flags", str(res / "flags.json")),
                          ("--format", "table"),
                          ("--out", str(res / "report.json")),
                      ])))
        if mode == "synthetic":
            steps.append(("Validate against synthetic ground truth", "cli_save",
                          (_command_args("validate", [
                              ("--flags", str(res / "flags.json")),
                              ("--synth-ground-truth", str(src / "ground_truth.parquet")),
                          ]), res / "validation.txt")))
    except ValueError as exc:
        meta["command_error"] = str(exc)
        _write_meta(rd, meta)
        st.error(f"CLI command preflight failed: {exc}")
        return

    st.subheader(f"Running pipeline — {name}")
    st.caption("The CLI runs synchronously with argument lists; captured output and elapsed "
               "time are shown per step. Large runs may take minutes.")
    for label, kind, payload in steps:
        with st.status(label, expanded=True) as stt:
            if kind == "local":
                res_step = payload()
            elif kind == "cli_save":
                args, savep = payload
                res_step = run_cli(args)
                if res_step["ok"]:
                    Path(savep).parent.mkdir(parents=True, exist_ok=True)
                    Path(savep).write_text(res_step["output"], encoding="utf-8")
            else:
                res_step = run_cli(payload)
            if res_step.get("cmd"):
                st.caption("command: `" + " ".join(res_step["cmd"]) + "`")
            output = res_step.get("output") or "(no output)"
            excerpt = _command_output_excerpt(output)
            st.code(excerpt, language="text")
            meta["steps"].append(dict(
                label=label, ok=bool(res_step["ok"]), rc=res_step.get("returncode"),
                elapsed=round(float(res_step.get("elapsed", 0)), 1),
                cmd=res_step.get("cmd"), output=excerpt))
            _write_meta(rd, meta)
            if res_step["ok"]:
                stt.update(label=f"{label} — {res_step.get('elapsed', 0):.1f}s",
                           state="complete", expanded=False)
            else:
                stt.update(label=f"{label} — failed", state="error", expanded=True)
                st.error(f"Step failed: {label}. Artifacts saved so far are in runs/{name}/.")
                st.stop()

    meta["finished"] = now_iso()
    _write_meta(rd, meta)
    st.cache_data.clear()
    ss.active_run = name          # sidebar selectbox resyncs via the reset trick
    ss.active_entity_id = None
    ss.open_finding_id = None
    ss.findings_filter = {}
    sync_params()
    st.success(f"Assessment “{name}” complete — artifacts under runs/{name}/ "
               f"(source · normalized · results).")
    if st.button("Open Portfolio overview", type="primary"):
        go("portfolio")


def render_run_page():
    st.header("Run assessment")
    st.caption("One Start action runs validation → analysis → scoring → publishing through "
               "the real SAT-SA CLI. The UI is a presentation layer: it drives `satsa` with "
               "argument lists and reads its artifacts — no analytics are duplicated.")

    if _detect_cli() is None:
        st.error("SAT-SA CLI not found in this environment. Install the `sat_sa` package in "
                 "the same virtualenv as Streamlit (`pip install -e .`), or ensure the "
                 "`satsa` command is on PATH.")

    runs = list_runs()
    if runs:
        with st.expander(f"Existing runs ({len(runs)})"):
            df = pd.DataFrame([dict(run=r["name"], mode=r["mode"], created=r["created"][:19],
                                    status=run_status_line(r["name"]))
                               for r in runs])
            show_table(df, hide_index=True)
            if st.button("Open latest run in Portfolio"):
                ss.active_run = runs[0]["name"]
                go("portfolio")

    st.subheader("New assessment run")
    name = st.text_input("Run name", value=_default_run_name(), key="new_run_name",
                         help="Sanitised to A–Z a–z 0–9 _ - (max 64). Each run is isolated "
                              "under runs/<name>/ so demos never overwrite each other.")
    safe = sanitize_run_name(name)
    st.caption(f"Run directory: runs/{safe}/")
    if (RUNS_DIR / safe).exists():
        st.warning(f"Run “{safe}” already exists. The pipeline is not resumable and will "
                   f"overwrite named output files — prefer a fresh run name.")

    route = st.radio("Data route",
                     ["Synthetic (deterministic demo data)", "Upload CSV submission"],
                     horizontal=True, key="route")
    params = dict(mode="synthetic")

    if route.startswith("Synthetic"):
        def _preset_changed():
            e, a = PRESETS[ss.preset]
            ss.pf_entities, ss.pf_ape = e, a
        st.selectbox("Preset", list(PRESETS), key="preset", on_change=_preset_changed)
        c1, c2, c3, c4 = st.columns(4)
        c1.number_input("CSEs (entities)", min_value=4, key="pf_entities")
        c2.number_input("Baseline alerts per CSE", min_value=1, step=500,
                        key="pf_ape")
        c3.number_input("Anomaly rate", min_value=0.01, max_value=1.0,
                        step=0.05, format="%.2f", key="pf_anom")
        c4.number_input("Seed", min_value=0, key="pf_seed")
        st.toggle("Adaptive runtime", key="pf_adaptive",
                  help="Adaptive mode grows/shrinks batch size & workers from host memory, "
                       "CPU and throughput. Turn off for reproducible benchmarks.")
        with st.expander("Advanced runtime (reproducibility)"):
            st.number_input("Batch size (0 = auto)", min_value=0, step=1000,
                            key="pf_batch")
            st.number_input("Workers (0 = auto)", min_value=0, key="pf_workers")
            st.number_input("Healthcheck interval (batches)", min_value=1,
                            key="pf_hc")
            st.text_input("Detector config YAML (optional, relative to app dir)", key="pf_cfg")
        total = int(ss.pf_entities * ss.pf_ape) + 2 * max(1, round(ss.pf_entities * ss.pf_anom))
        st.caption(f"Estimated total alerts ≈ {fmt_int(total)} "
                   f"(D1 and D2 each add one alert per selected entity).")
        if total > 500_000:
            st.warning("Very large run — expect minutes of CLI runtime; this page stays busy "
                       "until the pipeline finishes (no background polling by design).")
        params = dict(mode="synthetic", entities=int(ss.pf_entities), ape=int(ss.pf_ape),
                      anomaly=float(ss.pf_anom), seed=int(ss.pf_seed),
                      adaptive=bool(ss.pf_adaptive), batch=int(ss.pf_batch),
                      workers=int(ss.pf_workers), hc=int(ss.pf_hc), config=ss.pf_cfg)
        can_start = bool(safe) and not (RUNS_DIR / safe).exists()
    else:
        files = st.file_uploader("Upload the five submission CSVs (entities, assets, alerts, "
                                 "cases, escalations — cases/escalations may be header-only "
                                 "empty files)", type=["csv"], accept_multiple_files=True,
                                 key="up_files")
        stems = {}
        for f in files or []:
            stem = Path(f.name).stem.lower()
            if stem in RUN_TABLES:
                stems[stem] = f
        staged_on_disk = {t for t in RUN_TABLES
                          if (RUNS_DIR / safe / "source" / f"{t}.csv").exists()}
        present = set(stems) | staged_on_disk
        cc = st.columns(5)
        for col, t in zip(cc, RUN_TABLES):
            col.metric(t, "present" if t in present else "missing")
        if files and any(Path(f.name).stem.lower() not in RUN_TABLES for f in files):
            st.warning("Extra files are skipped by ingestion with a warning "
                       "(only the five logical tables are read).")
        if stems:
            info = []
            for stem, f in stems.items():
                try:
                    dfp = pd.read_csv(f)
                    missing = [c for c in REQUIRED_COLS[stem] if c not in dfp.columns]
                    info.append(dict(table=stem, rows=len(dfp),
                                     missing_required_cols=", ".join(missing) or "—"))
                except Exception as e:
                    info.append(dict(table=stem, rows="—", missing_required_cols=str(e)[:80]))
            show_table(pd.DataFrame(info), hide_index=True)
        can_start = present == set(RUN_TABLES) and bool(safe) and not (RUNS_DIR / safe).exists()
        if not can_start:
            st.info("Validation is enabled only once all five logical tables are present "
                    "(spec: intake requires all five, even if cases/escalations are empty).")
        params = dict(mode="upload", adaptive=True, batch=0, workers=0, hc=4,
                      config="detector_config.yaml")

    if st.button("Start assessment", type="primary", disabled=not can_start):
        run_pipeline(safe, params["mode"], params,
                     uploads=stems if params["mode"] == "upload" else {})


# ----------------------------------------------------------------------------- Portfolio page
def portfolio_frame(run_dir: str):
    scores = load_scores(run_dir)
    if scores.empty:
        return None
    ent = load_entities(run_dir)
    vol = load_volumes(run_dir)
    names = entity_names(run_dir)
    emap = ent.set_index("entity_id") if not ent.empty else None
    hist = _history_df()
    prior = prior_run(Path(run_dir).name)
    prior_ent = prior_flag_entities(prior["dir"]) if prior else frozenset()

    universe = list(dict.fromkeys(
        [str(x) for x in scores["entity_id"]] +
        ([str(x) for x in ent["entity_id"]] if not ent.empty else [])))
    rows = []
    for e in universe:
        s = scores[scores["entity_id"] == e]
        srow = s.iloc[0] if len(s) else None
        counts = srow["_counts"] if srow is not None else {}
        risk = float(srow["risk_score"]) if srow is not None else 0.0
        volume = int(vol.get(e, srow["alert_volume"] if srow is not None else 0) or 0)
        eg = 2 * int(counts.get("fast_closure", 0)) + 3 * int(counts.get("no_escalation", 0))
        ns = 2 * int(counts.get("low_coverage", 0))
        sector = "—"
        peer = "—"
        if emap is not None:
            if "sector" in emap.columns and e in emap.index:
                sector = emap.at[e, "sector"]
            if "peer_group" in emap.columns and e in emap.index:
                peer = emap.at[e, "peer_group"]
        h = hist[hist["entity_id"] == e].sort_values("cycle_order") if not hist.empty else pd.DataFrame()
        trend = [round(float(v), 3) for v in h["risk_score"].tail(4)] if len(h) else [round(risk, 3)]
        rank = int(srow["priority_rank"]) if (srow is not None and pd.notna(srow["priority_rank"])) else None
        rows.append(dict(entity_id=e, entity=names.get(e, e), sector=str(sector),
                         peer_group=str(peer), risk=risk, rank=rank, eg=eg, ns=ns,
                         volume=volume, flagged=(eg + ns) > 0,
                         new=((eg + ns) > 0 and e not in prior_ent), trend=trend))
    df = pd.DataFrame(rows)
    if df.empty:
        return None
    df["peer_pct"] = df.groupby("peer_group")["risk"].rank(pct=True, method="average") * 100
    df["status"] = [("submitted" if v > 0 else "no alerts") for v in df["volume"]]
    known = set(ent["entity_id"].astype(str)) if not ent.empty else set()
    df.loc[~df["entity_id"].isin(known), "status"] = "not in entities table"
    return df


def render_portfolio(run_dir: str):
    st.header("Portfolio overview")
    st.caption("Triage across the whole CSE portfolio for the selected cycle. Summary surface "
               "only — built from the scored findings rollup, not raw alerts. Row click opens "
               "the entity profile.")
    df = portfolio_frame(run_dir)
    if df is None:
        st.warning("Scoring artifacts missing for this cycle (entity_scores.csv). Re-run the "
                   "pipeline from Run assessment.")
        if st.button("Go to Run assessment"):
            go("run")
        return

    hist = _history_df()
    delta = None
    if not hist.empty:
        cur = hist[hist["cycle"] == Path(run_dir).name]
        if not cur.empty:
            o = int(cur["cycle_order"].max())
            prv = hist[hist["cycle_order"] == o - 1]
            if not prv.empty:
                delta = float(cur["risk_score"].mean() - prv["risk_score"].mean())

    m = st.columns(5)
    m[0].metric("CSEs assessed", fmt_int(len(df)))
    m[1].metric("Flagged (EG)", fmt_int((df["eg"] > 0).sum()),
                help="Entities with execution-gap findings (D1 fast closure, D2 no escalation).")
    m[2].metric("Flagged (NS)", fmt_int((df["ns"] > 0).sum()),
                help="Entities with negative-space findings (D3 low critical-asset coverage).")
    m[3].metric("No submission / no alerts", fmt_int((df["status"] != "submitted").sum()))
    m[4].metric("Avg portfolio risk", f"{df['risk'].mean():.2f}",
                delta=(f"{delta:+.2f}" if delta is not None else None),
                delta_color="inverse", help="Mean risk_score this cycle vs previous cycle.")

    fc = st.columns(4)
    sector = fc[0].multiselect("Sector", sorted(set(df["sector"])), key="pf_sector")
    mxr = float(max(round(df["risk"].max() * 1.05, 2), 0.5))
    mn = fc[1].slider("Min risk", 0.0, mxr, 0.0, round(mxr / 50, 2) or 0.01, key="pf_min")
    newonly = fc[2].toggle("New this cycle only", key="pf_new")
    stat = fc[3].selectbox("Submission status",
                           ["All", "submitted", "no alerts", "not in entities table"],
                           key="pf_status")

    view = df.copy()
    if sector:
        view = view[view["sector"].isin(sector)]
    view = view[view["risk"] >= mn]
    if newonly:
        view = view[view["new"]]
    if stat != "All":
        view = view[view["status"] == stat]
    view = view.sort_values(["risk", "eg", "ns"], ascending=False)

    disp = pd.DataFrame({
        "Entity": view["entity"] + " (" + view["entity_id"] + ")",
        "Sector": view["sector"],
        "Risk": view["risk"].round(3),
        "EG": view["eg"],
        "NS": view["ns"],
        "Peer %ile": view["peer_pct"].round(0),
        "Trend": view["trend"],
        "New": ["new" if x else "" for x in view["new"]],
        "Submission": view["status"],
    })
    ids = list(view["entity_id"])
    cc = {
        "Entity": st.column_config.TextColumn("Entity", width="medium"),
        "Sector": st.column_config.TextColumn("Sector", width="small"),
        "Risk": st.column_config.ProgressColumn(
            "Overall risk", min_value=0.0, max_value=float(max(view["risk"].max(), 1.0)),
            format="%.2f"),
        "EG": st.column_config.NumberColumn("EG sub-score", format="%.0f",
                                            help="Σ weight × flags for D1 (2) and D2 (3)."),
        "NS": st.column_config.NumberColumn("NS sub-score", format="%.0f",
                                            help="Σ weight × flags for D3 (2)."),
        "Peer %ile": st.column_config.NumberColumn(
            "Peer percentile", format="%.0f",
            help="Share of peer-group entities with lower risk (50 ≈ peer median)."),
        "Trend": st.column_config.LineChartColumn("4-cycle risk trend", width="small"),
        "New": st.column_config.TextColumn("New", width="small"),
        "Submission": st.column_config.TextColumn("Submission", width="small"),
    }
    ev = show_table(disp, column_config=cc, hide_index=True, key="pf_tbl",
                    on_select="rerun", selection_mode="single-row")
    rows = ev.selection.rows if (ev and hasattr(ev, "selection")) else []
    sig = tuple(rows)
    if sig and sig != ss.get("pf_lastsel"):
        ss.pf_lastsel = sig
        if rows:
            go("entity", entity=ids[rows[0]])

    b = st.columns(4)
    if b[0].button("View all findings"):
        ss.findings_filter = {}
        go("findings")
    if b[1].button("Review queue"):
        go("queue")
    if b[2].button("Data health (no-submission entities)"):
        go("health")
    if b[3].button("Portfolio summary report"):
        go("reports")

    with st.expander("Synthetic ground-truth validation"):
        show_validation_panel(run_dir, key_prefix="pfval")


# ----------------------------------------------------------------------------- Entity profile page
def _entity_picked():
    ss.active_entity_id = ss.entity_pick
    sync_params()


def _peer_med(m: pd.DataFrame, pg, col):
    if m is None or pg is None or col not in m.columns:
        return None
    sub = m[(m["peer_group"] == pg)][col].dropna()
    return float(sub.median()) if len(sub) else None


def render_entity_page(run_dir: str):
    st.header("Entity profile")
    ent = load_entities(run_dir)
    scores = load_scores(run_dir)
    names = entity_names(run_dir)
    ids: list[str] = []
    if not ent.empty:
        ids += [str(x) for x in ent["entity_id"]]
    if not scores.empty:
        ids += [str(x) for x in scores["entity_id"]]
    ids = sorted(set(ids))
    if not ids:
        st.info("No entities in this run yet.")
        return
    eid = ss.get("active_entity_id")
    if eid not in ids:
        pick = st.selectbox("Entity", ids, index=0,
                            format_func=lambda i: f"{i} — {names.get(i, i)}",
                            key="entity_pick", on_change=_entity_picked)
        eid = pick
    elif "entity_pick" in ss:
        try:
            del ss["entity_pick"]
        except Exception:
            pass

    emap = ent.set_index("entity_id") if not ent.empty else None
    sector = str(emap.at[eid, "sector"]) if (emap is not None and "sector" in emap.columns
                                             and eid in emap.index) else "—"
    peer = str(emap.at[eid, "peer_group"]) if (emap is not None and "peer_group" in emap.columns
                                               and eid in emap.index) else "—"
    srow = None
    if not scores.empty:
        s = scores[scores["entity_id"] == eid]
        srow = s.iloc[0] if len(s) else None
    counts = srow["_counts"] if srow is not None else {}
    risk = float(srow["risk_score"]) if srow is not None else 0.0
    rank = int(srow["priority_rank"]) if (srow is not None and pd.notna(srow["priority_rank"])) else None
    eg = 2 * int(counts.get("fast_closure", 0)) + 3 * int(counts.get("no_escalation", 0))
    ns = 2 * int(counts.get("low_coverage", 0))
    vol = int(load_volumes(run_dir).get(eid, (srow["alert_volume"] if srow is not None else 0)) or 0)

    pct = float(scores["risk_score"].quantile(0.75)) if not scores.empty else 0
    med = float(scores["risk_score"].quantile(0.5)) if not scores.empty else 0
    band = ("high" if risk >= pct and risk > 0 else
            ("medium" if risk >= med and risk > 0 else "low"))
    h1, h2 = st.columns([3, 2])
    with h1:
        st.markdown(f"### {esc(names.get(eid, eid))}")
        st.caption(f"{esc(eid)} · sector {esc(sector)} · peer group {esc(peer)} · "
                   f"cycle {esc(ss.get('active_run'))}")
        st.markdown(
            pill(f"RISK {risk:.2f}", SEV_COLOR["critical"] if risk >= pct else
                 (SEV_COLOR["high"] if risk >= med else SEV_COLOR["low"])) + " " +
            pill(f"band {band}", "#5d6d7e") + " " +
            (pill(f"EG ×{int(counts.get('fast_closure', 0) + counts.get('no_escalation', 0))}", FAM_COLOR["EG"]) + " " if eg else "") +
            (pill(f"NS ×{int(counts.get('low_coverage', 0))}", FAM_COLOR["NS"]) if ns else ""),
            unsafe_allow_html=True)
    with h2:
        c1, c2, c3 = st.columns(3)
        c1.metric("Risk", f"{risk:.2f}")
        c2.metric("Priority rank", rank if rank else "—")
        c3.metric("Alert volume", fmt_int(vol))
    b = st.columns(4)
    if b[0].button("Compare to peers"):
        go("benchmark")
    if b[1].button("Generate entity report"):
        go("reports")
    if b[2].button("View submission status"):
        go("health")
    if b[3].button("Back to portfolio"):
        go("portfolio")

    t1, t2, t3, t4, t5 = st.tabs(["Overview", "Alerts & cases", "Coverage",
                                  "Findings", "History"])
    m = entity_metrics(run_dir)
    mrow = m[m["entity_id"] == eid].iloc[0] if ((not m.empty) and (eid in set(m["entity_id"]))) else None

    # ---- Overview -----------------------------------------------------------
    with t1:
        hist = _history_df()
        h = hist[hist["entity_id"] == eid].sort_values("cycle_order") if not hist.empty else pd.DataFrame()
        delta = None
        if len(h) >= 2:
            delta = float(h["risk_score"].iloc[-1] - h["risk_score"].iloc[-2])
        c1, c2 = st.columns([2, 3])
        with c1:
            st.markdown("**Score composition** (risk is Σ weight × flags ÷ log(1 + alert volume))")
            bar_chart(pd.Series({
                "EG (weighted)": eg, "NS (weighted)": ns,
                "Δ risk vs prior cycle": (round(delta, 2) if delta is not None else 0.0),
            }))
            peer_pct = None
            if mrow is not None and peer != "—":
                sub = m[m["peer_group"] == peer]["risk_score"].dropna()
                if len(sub):
                    peer_pct = round(100 * (sub < risk).mean(), 0)
            st.metric("Peer deviation percentile", peer_pct if peer_pct is not None else "—",
                      help="Share of peer-group entities with lower risk.")
        with c2:
            g1, g2, g3 = st.columns(3)
            g1.metric("Alert volume", fmt_int(vol),
                      help=f"peer median: {fmt_int(_peer_med(m, peer, 'alert_volume'))}")
            g2.metric("Escalation rate", fmt_pct(mrow["escalation_rate"] if mrow is not None else None),
                      help=f"peer median: {fmt_pct(_peer_med(m, peer, 'escalation_rate'))}")
            g3.metric("Closure rate", fmt_pct(mrow["closure_rate"] if mrow is not None else None),
                      help=f"peer median: {fmt_pct(_peer_med(m, peer, 'closure_rate'))}")
            g4, g5, g6 = st.columns(3)
            g4.metric("Avg case closure (h)",
                      (f"{mrow['avg_case_closure_hrs']:.1f}" if (mrow is not None and mrow["avg_case_closure_hrs"] is not None) else "—"),
                      help=f"peer median: "
                           f"{(_peer_med(m, peer, 'avg_case_closure_hrs') or float('nan')):.1f}"
                           if _peer_med(m, peer, "avg_case_closure_hrs") is not None else "n/a")
            g5.metric("Ack rate", fmt_pct(mrow["ack_rate"] if mrow is not None else None),
                      help=f"peer median: {fmt_pct(_peer_med(m, peer, 'ack_rate'))}")
            assets = load_assets(run_dir)
            g6.metric("Assets", fmt_int((assets["entity_id"] == eid).sum()) if not assets.empty else 0)

    # ---- Alerts & cases ----------------------------------------------------
    with t2:
        alerts = load_entity_alerts(run_dir, eid)
        flags = load_flags(run_dir)
        fmap = {}
        for f in flags:
            if str(f.get("entity_id")) == eid and f.get("detector") in ("fast_closure", "no_escalation"):
                for a in (f.get("evidence") or {}).get("alert_ids") or []:
                    fmap[str(a)] = f.get("flag_id")
        if alerts.empty:
            st.caption("No alerts for this entity — see Data health (submitted vs sparse vs missing).")
        else:
            alerts = alerts.copy()
            alerts["flagged"] = ["flagged" if str(a) in fmap else "" for a in alerts.get("alert_id", [])]
            alerts = alerts.sort_values("created_at", ascending=False) if "created_at" in alerts else alerts
            n = st.slider("Rows displayed", 50, max(50, min(len(alerts), 5000)),
                          min(500, len(alerts)), step=50, key=f"ea_n_{eid}")
            adisp = alerts.head(n)
            show_cols = [c for c in ["alert_id", "severity", "category", "disposition",
                                     "escalated", "created_at", "first_ack_at", "closed_at",
                                     "asset_id", "case_id", "flagged"] if c in adisp.columns]
            ev = show_table(adisp[show_cols], hide_index=True, key=f"ea_tbl_{eid}",
                            on_select="rerun", selection_mode="single-row")
            rows = ev.selection.rows if (ev and hasattr(ev, "selection")) else []
            if rows:
                rec = adisp.iloc[rows[0]]
                with st.expander("Raw record", expanded=True):
                    st.table(pd.DataFrame({"field": list(rec.index),
                                           "value": [str(v) for v in rec.values]}))
                fid = fmap.get(str(rec.get("alert_id")))
                if fid and st.button(f"Open finding {fid}", key=f"ea_open_{eid}"):
                    open_finding(fid)
        st.markdown("##### Cases")
        cases = load_entity_cases(run_dir, eid)
        if cases.empty:
            st.caption("No cases for this entity.")
        else:
            cdisp = cases.copy()
            if "alert_ids" in cdisp.columns:
                cdisp["alert_ids"] = cdisp["alert_ids"].map(
                    lambda v: ", ".join(map(str, v)) if isinstance(v, (list, tuple)) else str(v))
            show_table(cdisp, hide_index=True, key=f"ec_tbl_{eid}")

    # ---- Coverage ----------------------------------------------------------
    with t3:
        assets = load_assets(run_dir)
        a_e = assets[assets["entity_id"] == eid] if not assets.empty else pd.DataFrame()
        alerts = load_entity_alerts(run_dir, eid)
        d3 = [f for f in flags if str(f.get("entity_id")) == eid
              and f.get("detector") == "low_coverage"]
        peer_med = None
        if d3:
            try:
                peer_med = float((d3[0].get("evidence") or {}).get("peer_median"))
            except (TypeError, ValueError):
                peer_med = None
        ref = alerts["created_at"].max() if ("created_at" in alerts and len(alerts)) else None
        counts = {}
        if ref is not None:
            win = alerts[alerts["created_at"] >= ref - pd.Timedelta(days=30)]
            if "asset_id" in win:
                counts = win["asset_id"].value_counts().to_dict()
        rowsc = []
        for _, r in a_e.iterrows():
            aid = str(r.get("asset_id"))
            crit = str(r.get("criticality", ""))
            n = int(counts.get(aid, 0)) + int(counts.get(r.get("asset_id"), 0))
            if crit == "critical":
                if n == 0:
                    stt = "no telemetry"
                elif peer_med and n < 0.25 * peer_med:
                    stt = f"sparse ({n} vs median {peer_med:.0f})"
                else:
                    stt = f"nominal ({n})"
            else:
                stt = "– non-critical" if n == 0 else str(n)
            rowsc.append(dict(asset_id=aid, criticality=crit,
                              asset_type=str(r.get("asset_type", "—")),
                              recent_alerts_30d=n, telemetry=stt))
        if rowsc:
            cdf = pd.DataFrame(rowsc)
            cdf["_cr"] = cdf["criticality"].map({"critical": 0, "high": 1, "medium": 2, "low": 3}).fillna(9)
            cdf = cdf.sort_values("_cr").drop(columns=["_cr"]).reset_index(drop=True)
            sty = cdf.style
            sty = styler_map(sty, lambda v: (
                "background-color:#fadbd8;color:#943126;font-weight:600" if str(v).startswith("no telemetry") else
                "background-color:#fdebd0;color:#9c640c;font-weight:600" if str(v).startswith("sparse") else
                "background-color:#d4efdf;color:#186a3b;font-weight:600" if str(v).startswith("nominal") else
                ""), subset=["telemetry"])
            if hasattr(sty, "hide"):
                sty = sty.hide(axis="index")
            st.caption("Critical assets generating little or no telemetry — the D3 question. "
                       f"Peer cohort median from D3 evidence: {peer_med if peer_med is not None else 'n/a'}; "
                       "sparse = < 25% of median over the 30-day window ending at the latest alert.")
            show_table(sty)
        else:
            st.caption("No assets recorded for this entity.")

    # ---- Findings ----------------------------------------------------------
    with t4:
        render_findings_table(run_dir, entity_id=eid, key_prefix=f"ef_{eid}")

    # ---- History -----------------------------------------------------------
    with t5:
        if len(h) <= 1:
            st.caption("Only one cycle recorded for this entity so far — trends and recurrence "
                       "appear after subsequent runs (each run = one cycle).")
        else:
            hh = h.set_index("cycle")
            c1, c2, c3 = st.columns(3)
            c1.metric("Risk (latest)", f"{h['risk_score'].iloc[-1]:.2f}")
            c2.metric("Alert volume (latest)", fmt_int(h['alert_volume'].iloc[-1]))
            c3.metric("Flags (latest)", fmt_int(h['flag_count'].iloc[-1]))
            g1, g2, g3 = st.columns(3)
            with g1:
                st.caption("Risk score"); line_chart(hh["risk_score"])
            with g2:
                st.caption("Alert volume"); line_chart(hh["alert_volume"])
            with g3:
                st.caption("Flag count"); line_chart(hh["flag_count"])
        others = [c for c in h["cycle"].unique() if c != Path(run_dir).name] if len(h) else []
        if others:
            pick = st.selectbox("Compare with cycle", others, key="ent_cmp")
            o = h[h["cycle"] == pick]
            if len(o):
                r0 = o.iloc[0]
                cc = st.columns(3)
                cc[0].metric("Risk then", f"{r0['risk_score']:.2f}", f"{risk - r0['risk_score']:+.2f}",
                             delta_color="inverse")
                cc[1].metric("Alerts then", fmt_int(r0["alert_volume"]))
                cc[2].metric("Flags then", fmt_int(r0["flag_count"]))
        cur = [f for f in flags if str(f.get("entity_id")) == eid]
        rec = []
        for f in cur:
            cycles = _finding_cycles(eid, finding_key(f))
            if len(cycles) > 1:
                det = RULE_META.get(f.get("detector"), {}).get("rule", f.get("detector"))
                rec.append(f"Recurring: {det} · key {finding_key(f)[1]} — cycles: {', '.join(cycles)}")
        if rec:
            st.markdown("**Recurring findings** (entity didn't fix what was flagged last cycle):")
            st.markdown("\n".join(f"- {r}" for r in rec))
        elif cur:
            st.caption("No recurring findings across cycles for this entity.")


# ----------------------------------------------------------------------------- Findings page
def render_findings_page(run_dir: str):
    st.header("Findings feed")
    st.caption("The working list of supervisory findings. EG (execution gaps: D1, D2) and "
               "NS (negative space: D3) are always separate tables — never merged.")
    ent = load_entities(run_dir)
    with st.sidebar:
        st.markdown("#### Findings filters")
        ids = sorted({str(x) for x in ent["entity_id"]}) if not ent.empty else []
        f_entities = st.multiselect("Entity", ids, key="ff_ent")
        sectors = sorted({str(x) for x in ent["sector"].dropna()}) if (not ent.empty and "sector" in ent) else []
        f_sector = st.multiselect("Sector", sectors, key="ff_sector")
        f_sev = st.multiselect("Severity", ["critical", "high", "medium", "low"], key="ff_sev")
        f_cap = st.multiselect("Capability area", CAPABILITIES, key="ff_cap")
        f_det = st.multiselect("Detector rule", list(RULE_META),
                               format_func=lambda d: RULE_META[d]["rule"], key="ff_det")
        f_disp = st.selectbox("Disposition", ["Any"] + ["—"] + DISP_OPTIONS, key="ff_disp")
    filters = dict(entities=f_entities, sector=f_sector, severity=f_sev,
                   capability=f_cap, detector=f_det, disposition=f_disp)
    tab_eg, tab_ns = st.tabs(["Execution gaps (D1 · D2)", "Negative space (D3)"])
    with tab_eg:
        render_findings_table(run_dir, family="EG", filters=filters, key_prefix="ff_eg")
    with tab_ns:
        render_findings_table(run_dir, family="NS", filters=filters, key_prefix="ff_ns")


# ----------------------------------------------------------------------------- Peer benchmarking page
def render_benchmark_page(run_dir: str):
    st.header("Peer benchmarking")
    st.caption("Gives “unexpectedly low / deviating from peers” a reference distribution: "
               "the entity is a marker on the cohort box plot, with the ranked numbers below. "
               "Sector-scoped by design — a power-grid CSE and a bank never share a cohort.")
    m = entity_metrics(run_dir)
    if m.empty:
        st.info("No entity metrics yet — run the pipeline first.")
        return
    groups = sorted(set(m["peer_group"]))
    default_gi = 0
    eid = ss.get("active_entity_id")
    if eid and eid in set(m["entity_id"]):
        pg0 = m.loc[m["entity_id"] == eid, "peer_group"].iloc[0]
        if pg0 in groups:
            default_gi = groups.index(pg0)
    pg = st.selectbox("Peer group", groups, index=default_gi, key="bm_group")
    metric = st.selectbox("Metric", list(BM_METRICS), format_func=lambda k: BM_METRICS[k],
                          key="bm_metric")
    guide = BM_METRIC_GUIDE[metric]
    metric_display = BM_METRICS[metric] + (" (%)" if guide["unit"] == "percent" else "")
    with st.expander("What this chart means", expanded=True):
        st.write(guide["definition"])
        st.caption(guide["read"])
        st.caption("The box shows the middle 50% of the selected peer group; the line inside is its median. "
                   "The red marker is the focus entity. Missing observations are excluded from the chart.")
    sub = m[m["peer_group"] == pg].copy()
    if sub.empty or metric not in sub.columns:
        st.caption("No data for this peer group / metric.")
        return
    # Keep cohort rows for the table, but ensure the metric is numeric. Some
    # aggregates intentionally return None when there is no denominator (for
    # example, no closed cases); object-typed None values cannot be rounded.
    sub[metric] = pd.to_numeric(sub[metric], errors="coerce")
    sub2 = sub.dropna(subset=[metric])
    focus_opts = list(sub["entity_id"])
    default_fi = 0
    if eid in focus_opts:
        default_fi = focus_opts.index(eid)
    focus = st.selectbox("Focus entity", focus_opts, index=default_fi,
                         format_func=lambda i: f"{i} — {sub.loc[sub['entity_id'] == i, 'entity'].iloc[0]}",
                         key="bm_focus")
    frow = sub[sub["entity_id"] == focus]
    fval = float(frow[metric].iloc[0]) if (len(frow) and pd.notna(frow[metric].iloc[0])) else None

    if not sub2.empty:
        if PLOTLY:
            fig = plotly_go.Figure()
            fig.add_trace(plotly_go.Box(y=sub2[metric], name="peer cohort", boxpoints="outliers",
                                 marker_color="#7f8c8d"))
            if fval is not None:
                fig.add_trace(plotly_go.Scatter(y=[fval], mode="markers", name=str(focus),
                                         marker=dict(color="#c0392b", size=13)))
            fig.update_layout(height=380, margin=dict(l=10, r=10, t=20, b=10),
                              showlegend=False, yaxis_title=metric_display,
                              yaxis=dict(tickformat=".0%" if guide["unit"] == "percent" else None))
            _st_chart(st.plotly_chart, fig)
        elif ALTAIR:
            box = alt.Chart(sub2).mark_boxplot(outliers=True).encode(
                y=alt.Y(metric, scale=alt.Scale(zero=False), title=metric_display,
                        axis=alt.Axis(format=".0%") if guide["unit"] == "percent" else alt.Axis()))
            layers = box
            if fval is not None:
                pt = alt.Chart(pd.DataFrame({metric: [fval]})).mark_point(
                    filled=True, size=130, color="#c0392b").encode(y=alt.Y(metric))
                layers = box + pt
            _st_chart(st.altair_chart, layers)
        else:
            st.caption("Install plotly (or rely on the bundled altair) for the distribution chart.")

    ranked = sub.copy()
    ranked["percentile"] = (ranked[metric].rank(pct=True, method="average") * 100).round(0)
    ranked["_focus"] = ["focus" if x == focus else "" for x in ranked["entity_id"]]
    ranked = ranked.sort_values(metric, ascending=False)
    display_metric = ranked[metric] * 100 if guide["unit"] == "percent" else ranked[metric]
    disp = pd.DataFrame({
        "Entity": ranked["entity"] + " (" + ranked["entity_id"] + ")",
        metric_display: display_metric.round(1 if guide["unit"] == "percent" else 3),
        "Percentile": ranked["percentile"],
        "Focus": ranked["_focus"],
    })
    ids = list(ranked["entity_id"])
    missing_count = int(ranked[metric].isna().sum())
    st.caption("Percentile = average-tie rank within the peer group (peer module contract). "
               + (f"{missing_count} entity/entities have no usable value and are shown as missing."
                  if missing_count else "All entities have a usable value."))
    ev = show_table(disp, hide_index=True, key="bm_tbl", on_select="rerun",
                    selection_mode="single-row")
    rows = ev.selection.rows if (ev and hasattr(ev, "selection")) else []
    sig = tuple(rows)
    if sig and sig != ss.get("bm_lastsel"):
        ss.bm_lastsel = sig
        if rows:
            go("entity", entity=ids[rows[0]])
    if st.button("Findings for this sector"):
        ss.findings_filter = {"sector_entities": None}
        ss.findings_filter = {}
        go("findings")


# ----------------------------------------------------------------------------- Review queue page
def render_queue_page(run_dir: str):
    st.header("Review queue")
    st.caption("The examiner's personal prioritized to-do list — the tool assists manual "
               "review, supervisory judgement stays human. Priority = severity weight "
               "(×1.5 if recurring) + risk ÷ 5. Status changes persist per cycle.")
    items = load_queue(run_dir)
    c1, c2 = st.columns([1, 3])
    c1.metric("Items", len(items))
    if c2.button("Add all undisposed findings to queue"):
        fv = findings_view(run_dir)
        added = 0
        for _, r in fv[fv["disposition"] == "—"].iterrows():
            ok, _ = add_finding_to_queue(run_dir, r["_flag"], bool(r["recurring"]))
            added += int(ok)
        st.toast(f"Added {added} findings to the queue.")
        st.rerun()
    if not items:
        st.info("Queue is empty. Add findings from the Findings feed (“Add to review "
                "queue”), from a finding's detail dialog, or with the bulk button above.")
        return
    for it in sorted(items, key=lambda x: -float(x.get("priority", 0))):
        with st.container(border=True):
            cc1, cc2, cc3, cc4, cc5 = st.columns([4, 1, 1.4, 1.4, 1])
            cc1.markdown(f"**{it.get('finding_id')}** · {esc(it.get('entity_id'))} · "
                         f"{severity_label(it.get('severity', ''))}")
            cc1.caption(f"{esc(it.get('reason', ''))} — ref {esc(it.get('ref', ''))}")
            cc2.metric("Priority", f"{float(it.get('priority', 0)):.1f}")
            st_status = it.get("status", "To review")
            cc3.selectbox("Status", ["To review", "In progress", "Done"],
                          index=["To review", "In progress", "Done"].index(st_status),
                          key=f"qs_{it['id']}", label_visibility="collapsed",
                          on_change=partial(_queue_field_cb, run_dir=run_dir,
                                            item_id=it["id"], field="status",
                                            key=f"qs_{it['id']}"))
            cc4.text_input("Assignee", value=it.get("assignee", "") or "",
                           key=f"qa_{it['id']}", label_visibility="collapsed",
                           on_change=partial(_queue_field_cb, run_dir=run_dir,
                                             item_id=it["id"], field="assignee",
                                             key=f"qa_{it['id']}"))
            if cc5.button("Open", key=f"qo_{it['id']}"):
                open_finding(it["finding_id"], entity=it.get("entity_id"))


# ----------------------------------------------------------------------------- Data health page
def health_matrix(run_dir: str) -> tuple[pd.DataFrame, list[str]]:
    ent = load_entities(run_dir)
    agg = alert_aggregates(run_dir)
    cases = case_aggregates(run_dir)
    assets = load_assets(run_dir)
    names = entity_names(run_dir)
    ent_ids: list[str] = []
    if not ent.empty:
        ent_ids += [str(x) for x in ent["entity_id"]]
    if not agg.empty:
        ent_ids += [str(x) for x in agg["entity_id"]]
    universe = list(dict.fromkeys(ent_ids))
    ar = agg.set_index("entity_id") if not agg.empty else None
    cr = cases.set_index("entity_id") if not cases.empty else None
    acounts = (assets["entity_id"].astype(str).value_counts().to_dict()
               if not assets.empty else {})

    def g(dfidx, col, e, default=0):
        if dfidx is None or e not in dfidx.index or col not in dfidx.columns:
            return default
        v = dfidx.at[e, col]
        return default if pd.isna(v) else v

    rows = []
    for e in universe:
        n = int(g(ar, "alerts", e))
        if n == 0:
            c_alert, c_inv, c_esc, c_clo = "none", "– n/a", "– n/a", "– n/a"
        else:
            c_alert = f"complete {n:,}"
            a = g(ar, "acked", e) / n
            c_inv = ("complete" if a >= 0.5 else ("partial" if a > 0 else "none")) + f" {a:.0%}"
            en = int(g(ar, "escalated", e))
            c_esc = ("complete" if en > 0 else "partial") + (f" {en:,}" if en else " none")
            cp = g(ar, "closed", e) / n
            c_clo = ("complete" if cp >= 0.5 else ("partial" if cp > 0 else "none")) + f" {cp:.0%}"
        nc = int(g(cr, "n_cases", e))
        c_case = ("complete" if nc > 0 else "partial") + (f" {nc:,}" if nc else " none")
        na = int(acounts.get(e, 0))
        c_asset = ("complete" if na >= 3 else ("partial" if na > 0 else "none")) + f" {na}"
        rows.append({"Entity": f"{names.get(e, e)} ({e})", "Alert metadata": c_alert,
                     "Case mgmt": c_case, "Investigation (ack)": c_inv,
                     "Escalation records": c_esc, "Disposition & closure": c_clo,
                     "Asset inventory": c_asset, "_eid": e})
    df = pd.DataFrame(rows)
    sparse = []
    if not df.empty:
        for _, r in df.iterrows():
            if any(str(r[c]).startswith("partial") for c in
                   ["Case mgmt", "Investigation (ack)", "Escalation records",
                    "Disposition & closure"]):
                sparse.append(r["_eid"])
    return df, sparse


def render_health_page(run_dir: str):
    st.header("Data health / submissions")
    st.caption("The key disambiguation: “CSE didn't submit” (compliance, none) vs "
               "“submitted and genuinely sparse” (real negative-space candidate, partial) vs "
               "“submitted & complete” (complete). Gray = not applicable.")
    df, sparse = health_matrix(run_dir)
    if df.empty:
        st.info("No entities found in this run.")
        return
    cols = ["Alert metadata", "Case mgmt", "Investigation (ack)", "Escalation records",
            "Disposition & closure", "Asset inventory"]
    sty = df[["Entity"] + cols].style
    sty = styler_map(sty, lambda v: (
        "background-color:#d4efdf;color:#186a3b;font-weight:600" if str(v).startswith("complete") else
        "background-color:#fdebd0;color:#9c640c;font-weight:600" if str(v).startswith("partial") else
        "background-color:#fadbd8;color:#943126;font-weight:600" if str(v).startswith("none") else
        "background-color:#eaecee;color:#797d7f"), subset=cols)
    if hasattr(sty, "hide"):
        sty = sty.hide(axis="index")
    show_table(sty)
    with st.expander("Cell rules"):
        st.markdown(
            "- **Alert metadata** complete if alerts>0, none otherwise\n"
            "- **Case mgmt** complete if cases>0, partial if the file is empty\n"
            "- **Investigation (ack)** complete at ≥50% acked, partial at 1–49%, none at 0%\n"
            "- **Escalation records** complete if any alert escalated, partial otherwise\n"
            "- **Disposition & closure** complete at ≥50% closed, partial at 1–49%, none at 0%\n"
            "- **Asset inventory** complete at ≥3, partial at 1–2, none at 0")
    if sparse:
        if st.button(f"View negative-space findings for the {len(sparse)} sparse (partial) entities"):
            ss.findings_filter = {"entities": sparse, "family": "NS"}
            go("findings")

    st.subheader("Ingestion quality (quarantine)")
    rejects = load_rejects(run_dir)
    if rejects:
        tcounts = pd.Series([r.get("table", "?") for r in rejects]).value_counts().to_dict()
        ent_counts = {}
        for r in rejects:
            e = (r.get("record") or {}).get("entity_id")
            if e:
                ent_counts[str(e)] = ent_counts.get(str(e), 0) + 1
        r1, r2 = st.columns(2)
        with r1:
            st.markdown("**Rejects per table** (rows that failed Pydantic validation and were "
                        "preserved in rejects.json — a spike here is itself worth attention)")
            show_table(pd.DataFrame([dict(table=k, rejects=v)
                                     for k, v in tcounts.items()]), hide_index=True)
        with r2:
            st.markdown("**Rejects per entity**")
            show_table(pd.DataFrame([dict(entity_id=k, rejects=v)
                                     for k, v in sorted(ent_counts.items(),
                                                        key=lambda kv: -kv[1])[:12]]),
                       hide_index=True)
        with st.expander(f"Inspect first {min(20, len(rejects))} reject records"):
            show_table(pd.DataFrame([
                dict(source=r.get("source", ""), table=r.get("table", ""), row=r.get("row"),
                     reason=json.dumps(r.get("reason", ""))[:160],
                     record=json.dumps(r.get("record", ""))[:160]) for r in rejects[:20]]),
                hide_index=True)
    else:
        st.caption("No rejected rows — every submitted record passed validation.")
    rows = []
    for t in RUN_TABLES:
        n = parquet_rows(Path(run_dir) / "normalized" / f"{t}.parquet")
        rows.append(dict(table=t, parquet_rows=(fmt_int(n) if n is not None else "—"),
                         rejects=tcounts.get(t, 0) if rejects else 0))
    st.markdown("**Normalized storage (Snappy Parquet row counts)**")
    show_table(pd.DataFrame(rows), hide_index=True)


# ----------------------------------------------------------------------------- Rules in effect page
def render_detectors_page(run_dir: str | None):
    st.header("Rules in effect")
    st.caption("Read-only view of the supervisory rules applied by each flagging engine. "
               "Select a row to filter the Findings feed to that detector.")

    if run_dir:
        meta = load_meta(run_dir)
        snapshot = meta.get("effective_detector_config")
        if snapshot:
            config = snapshot
            source = meta.get("detector_config_source", "run snapshot")
            st.info(f"Showing the exact configuration captured for cycle **{Path(run_dir).name}**. "
                    f"Source: `{source}`")
        else:
            cfgp = APP_DIR / "detector_config.yaml"
            config, source = effective_detector_config(cfgp)
            st.warning("Configuration snapshot unavailable for this legacy/external run; "
                       "showing the current configured values instead.")
    else:
        config, source = effective_detector_config(APP_DIR / "detector_config.yaml")
        st.info("No assessment run is selected. Showing the current configured values.")

    fired = (pd.Series([f.get("detector") for f in load_flags(run_dir)])
             .value_counts().to_dict()) if run_dir else {}
    k = float(config.get("fast_closure_k", DEFAULT_DETECTOR_CONFIG["fast_closure_k"]))
    wd = int(config.get("coverage_window_days", DEFAULT_DETECTOR_CONFIG["coverage_window_days"]))
    tp = float(config.get("coverage_threshold_pct", DEFAULT_DETECTOR_CONFIG["coverage_threshold_pct"]))
    ik = float(config.get("investigation_duration_k", DEFAULT_DETECTOR_CONFIG["investigation_duration_k"]))
    le = float(config.get("low_entity_activity_pct", DEFAULT_DETECTOR_CONFIG["low_entity_activity_pct"]))
    rm = int(config.get("recurrence_min_alerts", DEFAULT_DETECTOR_CONFIG["recurrence_min_alerts"]))
    wdv = float(config.get("workload_deviation_pct", DEFAULT_DETECTOR_CONFIG["workload_deviation_pct"]))
    mps = int(config.get("min_peer_sample", DEFAULT_DETECTOR_CONFIG["min_peer_sample"]))
    weights = {**DEFAULT_DETECTOR_CONFIG["weights"], **(config.get("weights") or {})}
    threshold = {
        "fast_closure": f"time_to_close < Q1 − {k:g} × IQR (severity-specific)",
        "no_escalation": "severity=critical ∧ disposition=true_positive ∧ escalated=false",
        "low_coverage": f"{wd}-day count < {tp:.0%} × peer median (critical assets)",
        "ack_without_meaningful_investigation": "severity∈{high,critical} ∧ acknowledged ∧ case exists ∧ root_cause_documented=false",
        "short_investigation": f"case duration < peer Q1 − {ik:g} × IQR (minimum {mps} peers)",
        "investigation_closure_mismatch": "severity∈{high,critical} ∧ true_positive ∧ closed ∧ case.root_cause_documented=false",
        "recurrence_without_root_cause": f"same entity+asset has ≥{rm} alerts with no documented root cause",
        "workload_severity_mismatch": f"case/high-critical-TP ratio < peer median × (1 − {wdv:.0%})",
        "high_risk_no_escalation": "severity=high ∧ disposition=true_positive ∧ escalated=false",
        "critical_asset_no_telemetry": f"critical asset observed_count=0 ∧ positive peer baseline ({wd}-day window)",
        "missing_investigation_evidence": "severity∈{high,critical} ∧ no matching case record",
        "missing_escalation_evidence": "escalated=true ∧ no matching escalation record",
        "low_entity_activity": f"entity alert count < {le:.0%} × peer median (minimum {mps} peers)",
    }
    st.caption(f"Configuration source: `{source}` · values are read-only")

    def rule_table(detectors):
        rows = []
        for det in detectors:
            rule = RULE_META[det]
            rows.append({
                "Rule": rule["rule"], "Plain-language description": rule["desc"],
                "Method": rule["method"], "Active condition": threshold[det],
                "Capability area": rule["capability"], "Family": family_label(rule["family"]),
                "Score weight": weights.get(det, rule["weight"]),
                "Fired this cycle": fired.get(det, 0),
            })
        return show_table(pd.DataFrame(rows), hide_index=True,
                          key=f"rules_{detectors[0]}", on_select="rerun",
                          selection_mode="single-row")

    tab_eg, tab_ns = st.tabs(["Execution gap rules", "Negative space rules"])
    with tab_eg:
        st.markdown("**Engine:** Execution gaps · identifies breakdowns in expected alert handling.")
        eg_event = rule_table(GROUP_DETECTORS["execution_gaps"])
    with tab_ns:
        st.markdown("**Engine:** Negative space · identifies likely monitoring blind spots.")
        ns_event = rule_table(GROUP_DETECTORS["negative_space"])

    selections = [(eg_event, GROUP_DETECTORS["execution_gaps"]),
                  (ns_event, GROUP_DETECTORS["negative_space"])]
    for event, detectors in selections:
        srows = event.selection.rows if (event and hasattr(event, "selection")) else []
        sig = tuple([detectors[0], *srows])
        if srows and sig != ss.get("rules_lastsel"):
            ss.rules_lastsel = sig
            ss.findings_filter = {"detector": detectors[srows[0]]}
            go("findings")


# ----------------------------------------------------------------------------- Report center page
def _report_data(run_dir: str, entity_id=None, include_disp=True):
    fv = findings_view(run_dir)
    if entity_id and not fv.empty:
        fv = fv[fv["entity_id"] == entity_id]
    disp_entries = {}
    if include_disp:
        for e in load_dispositions(run_dir):
            disp_entries.setdefault(e.get("finding_id"), []).append(e)
    return fv, disp_entries


def build_report_md(run_dir: str, scope: str, entity_id=None, include_disp=True) -> str:
    fv, disp = _report_data(run_dir, entity_id, include_disp)
    L = [f"# SAT-SA supervisory report — {scope}",
         f"Cycle (run): **{Path(run_dir).name}** · generated {now_iso()} · "
         f"examiner {esc(ss.get('examiner_name', '—'))}"]
    if scope == "Portfolio summary":
        df = portfolio_frame(run_dir)
        if df is not None:
            L += ["## Portfolio metrics",
                  f"- CSEs assessed: {len(df)}",
                  f"- Entities flagged (EG): {int((df['eg'] > 0).sum())}",
                  f"- Entities flagged (NS): {int((df['ns'] > 0).sum())}",
                  f"- No submission / no alerts: {int((df['status'] != 'submitted').sum())}",
                  f"- Average risk: {df['risk'].mean():.2f}",
                  "", "## Priority ranking (top 15)",
                  "| rank | entity | sector | risk | EG | NS |",
                  "|---:|---|---|---:|---:|---:|"]
            for _, r in df.sort_values("risk", ascending=False).head(15).iterrows():
                L.append(f"| {r['rank'] or '—'} | {r['entity']} ({r['entity_id']}) | "
                         f"{r['sector']} | {r['risk']:.2f} | {r['eg']} | {r['ns']} |")
        a = art(run_dir)
        if a["validation"].exists():
            m = parse_validation(a["validation"].read_text())
            if m:
                L += ["", "## Synthetic ground-truth validation"] + \
                     [f"- {k}: {v:g}" for k, v in m.items()]
    else:
        names = entity_names(run_dir)
        L += [f"## Entity: {names.get(entity_id, entity_id)} ({entity_id})"]
    L += ["", f"## Findings ({len(fv)})"]
    for _, r in (fv.iterrows() if not fv.empty else iter([])):
        L += [f"### {r['finding_id']} · {severity_label(r['severity'])} · "
              f"{r['family']} · {r['rule']}",
              f"> {r['rationale']}",
              f"- Why this fired: {why_line(r['_flag'])}",
              f"- Reference: {r['ref'] or '—'}",
              f"- Detected: {r['detected_at']}",
              f"- Recurring: {'yes' if r['recurring'] else 'no'}"]
        for e in disp.get(r["finding_id"], [])[-3:]:
            L.append(f"- Disposition ({e.get('ts')} · {esc(e.get('examiner'))}): "
                     f"{e.get('disposition')} — {esc(e.get('note', ''))}")
    L += ["", "*Findings are prioritisation signals for manual inspection — not proof of "
          "misconduct and not enforcement outcomes.*"]
    return "\n\n".join(L)


def build_report_html(run_dir: str, scope: str, entity_id=None, include_disp=True) -> str:
    md_body = build_report_md(run_dir, scope, entity_id, include_disp)
    # lightweight, dependency-free md → html for the subset we emit
    html_lines, in_table = [], False
    for line in md_body.splitlines():
        s = line.strip()
        if s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if not in_table:
                html_lines.append("<table>")
                in_table = True
            tag = "th" if not html_lines[-1].startswith("<tr") else "td"
            html_lines.append("<tr>" + "".join(f"<{tag}>{esc(c)}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            html_lines.append("</table>")
            in_table = False
        if s.startswith("# "):
            html_lines.append(f"<h1>{esc(s[2:])}</h1>")
        elif s.startswith("## "):
            html_lines.append(f"<h2>{esc(s[3:])}</h2>")
        elif s.startswith("### "):
            html_lines.append(f"<h3>{esc(s[4:])}</h3>")
        elif s.startswith("> "):
            html_lines.append(f"<blockquote>{esc(s[2:])}</blockquote>")
        elif s.startswith("- "):
            html_lines.append(f"<li>{esc(s[2:])}</li>")
        elif s.startswith("*") and s.endswith("*") and len(s) > 2:
            html_lines.append(f"<p><i>{esc(s[1:-1])}</i></p>")
        elif s:
            html_lines.append(f"<p>{esc(s)}</p>")
    if in_table:
        html_lines.append("</table>")
    return ("<!doctype html><html><head><meta charset='utf-8'><title>SAT-SA report</title>"
            "<style>body{font-family:Georgia,serif;max-width:860px;margin:32px auto;"
            "color:#222;line-height:1.5}table{border-collapse:collapse;margin:12px 0}"
            "th,td{border:1px solid #999;padding:4px 10px;font-size:0.92em}"
            "blockquote{border-left:4px solid #888;margin:8px 0;padding:2px 14px;"
            "color:#333}li{margin:2px 0}</style></head><body>"
            + "".join(html_lines) + "</body></html>")


def render_reports_page(run_dir: str):
    st.header("Report center")
    st.caption("Renders what the examiner already reviewed — findings, evidence lines and "
               "disposition notes. Nothing appears in the report that wasn't visible in the "
               "UI first. HTML/CSV/JSON exports are offline-safe; PDF needs WeasyPrint.")
    scope = st.radio("Report scope", ["Portfolio summary", "Entity assessment"],
                     horizontal=True, key="rp_scope")
    entity_id = None
    if scope == "Entity assessment":
        names = entity_names(run_dir)
        ids = sorted(names)
        if not ids:
            st.info("No entities available.")
            return
        default_i = 0
        if ss.get("active_entity_id") in ids:
            default_i = ids.index(ss["active_entity_id"])
        entity_id = st.selectbox("Entity", ids, index=default_i,
                                 format_func=lambda i: f"{i} — {names.get(i, i)}",
                                 key="rp_entity")
    include_disp = st.checkbox("Include disposition log", value=True, key="rp_disp")
    md = build_report_md(run_dir, scope, entity_id, include_disp)
    html = build_report_html(run_dir, scope, entity_id, include_disp)
    fv = findings_view(run_dir)
    if entity_id and not fv.empty:
        fv = fv[fv["entity_id"] == entity_id]
    csv_cols = [c for c in ["finding_id", "entity_id", "entity", "family", "detector", "rule",
                            "capability", "severity", "confidence", "detected_at",
                            "disposition", "recurring", "ref", "rationale"] if c in fv.columns]
    csv_bytes = (fv[csv_cols].to_csv(index=False).encode("utf-8") if not fv.empty else b"")
    slug = (entity_id or "portfolio").lower()

    st.subheader("Preview")
    with st.container(border=True, height=480):
        st.markdown(md)
    d1, d2, d3 = st.columns(3)
    d1.download_button("HTML report", data=html.encode("utf-8"),
                       file_name=f"satsa_{Path(run_dir).name}_{slug}.html", mime="text/html")
    d2.download_button("Findings CSV", data=csv_bytes,
                       file_name=f"satsa_{Path(run_dir).name}_{slug}_findings.csv",
                       mime="text/csv", disabled=not csv_bytes)
    a = art(run_dir)
    if a["report"].exists():
        d3.download_button("CLI report.json", data=a["report"].read_bytes(),
                           file_name=f"satsa_{Path(run_dir).name}_report.json",
                           mime="application/json")
    try:
        from weasyprint import HTML as _WHTML  # optional
        if st.button("Prepare PDF (WeasyPrint)"):
            ss["report_pdf"] = _WHTML(string=html).write_pdf()
        if ss.get("report_pdf"):
            st.download_button("Download PDF", data=ss["report_pdf"],
                               file_name=f"satsa_{Path(run_dir).name}_{slug}.pdf",
                               mime="application/pdf")
    except Exception:
        st.caption("PDF export requires WeasyPrint (`pip install weasyprint`) — HTML export "
                   "prints to PDF from any browser otherwise.")


# ----------------------------------------------------------------------------- How it works page
def render_how_page(rd):
    st.header("How SAT-SA works")
    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("""
```text
CSE submission (CSV / JSON)
        │
        v
Intake + validation (Pydantic v2) ── invalid rows → rejects.json (auditable)
        │ valid
        v
Normalized local Parquet (Snappy)
        │
        v  two-pass, bounded-memory scan
Detection: D1 fast closure · D2 no escalation · D3 low coverage
        │
        v
Evidence-attached flags.json (self-contained: rationale, baselines, source rows)
        │
        v
Entity risk scoring / priority ranking → entity_scores.csv
        │
        v
report.json · explain · synthetic validation
        │
        v
supervisory review (this workbench: dispositions, queue, reports)
```
""")
    with c2:
        st.markdown("""
- **Local & offline** — the runtime makes no network calls; this UI makes none either.
- **Bounded memory** — CSV ingestion and Parquet detection stream in batches; only counters,
  temporary duration files and findings are retained.
- **Adaptive runtime** — batch size / workers grow with headroom and back off under memory or
  throughput pressure (`--no-adaptive` for reproducible runs).
- **A flag is a prioritisation signal**, not proof of misconduct and not an enforcement outcome.
- One **cycle** in this UI = one isolated run directory under `runs/<name>/`
  (source · normalized · results), so separate demonstrations never overwrite each other.
- The pipeline is **not resumable** and overwrites named output files — use a fresh run name.
""")
    st.subheader("The three supervisory signals")
    show_table(pd.DataFrame([dict(
        Rule=RULE_META[d]["rule"], Question=RULE_META[d]["desc"],
        Method=RULE_META[d]["method"], Evidence=RULE_META[d].get("threshold", "—"),
        Family=family_label(RULE_META[d]["family"])
    ) for d in RULE_META]), hide_index=True)

    if rd:
        st.subheader(f"Pipeline status — cycle {Path(rd).name}")
        meta = load_meta(str(rd))
        steps = meta.get("steps", [])
        if steps:
            show_table(pd.DataFrame([dict(step=s.get("label"),
                                          result=("ok" if s.get("ok") else "failed"),
                                          rc=s.get("rc"), seconds=s.get("elapsed"))
                                     for s in steps]), hide_index=True)
            for s in steps:
                with st.expander(f"CLI output — {s.get('label')}"):
                    st.code((s.get("output") or "")[:4000], language="text")
        else:
            st.caption("No step metadata recorded (run created outside this UI).")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Host profile")
            if st.button("Run `satsa system-info`"):
                res = run_cli(["system-info"])
                if res["ok"]:
                    st.code(res["output"])
                    try:
                        j = json.loads(res["output"][res["output"].find("{"):])
                        st.json(j)
                    except Exception:
                        pass
                else:
                    st.error(res["output"][-1500:])
        with c2:
            st.markdown("#### Synthetic validation")
            show_validation_panel(str(rd), key_prefix="howval")
    st.subheader("Known constraints (by design)")
    st.caption("JSON is loaded as one document (CSV is the scalable path) · flags are held in "
               "memory (sparse by design) · generation is single-writer · no resume · no "
               "real-time monitoring · supervisory interpretation stays human.")


# ----------------------------------------------------------------------------- Finding detail (dialog)
def render_finding_detail(f: dict, run_dir: str):
    det = f.get("detector", "")
    ev = f.get("evidence") or {}
    meta = RULE_META.get(det, {})
    sev = finding_severity(f)
    fid = f.get("flag_id", "")
    st.markdown(
        pill(sev.upper(), SEV_COLOR.get(sev, "#5d6d7e")) + " " +
        pill(f"Family {FAMILY.get(det, '?')}", FAM_COLOR.get(FAMILY.get(det, ""), "#5d6d7e")) + " " +
        pill(meta.get("capability", ""), "#5d6d7e") + " " +
        pill(fid, "#34495e"),
        unsafe_allow_html=True)
    st.markdown(f"**{esc(f.get('rationale', ''))}**")
    st.caption(f"Entity {esc(f.get('entity_id'))} · detected {esc(f.get('generated_at', ''))} · "
               f"rule {meta.get('rule', det)}")

    with st.expander("Why this fired — the actual arithmetic", expanded=True):
        if det == "fast_closure":
            try:
                obs = float(ev.get("time_to_close_minutes"))
                q1 = float(ev.get("baseline_q1_minutes"))
                iqr = float(ev.get("baseline_iqr_minutes"))
                fence = q1 - 1.5 * iqr
                st.markdown(f"Method: **{meta.get('method')}**")
                show_table(pd.DataFrame(dict(quantity=[
                    "Observed time-to-close", "Severity baseline Q1", "IQR",
                    f"Lower fence (Q1 − 1.5 × IQR)", "Outlier factor (Q1 ÷ observed)",
                    "Baseline population"],
                    value=[fmt_minutes(obs), fmt_minutes(q1), fmt_minutes(iqr),
                           fmt_minutes(fence), f"{q1 / max(obs, 0.01):.1f}×",
                           str(ev.get("baseline_source", "—"))])), hide_index=True)
                st.caption("Flag condition: time_to_close < Q1 − 1.5 × IQR (strict; equality "
                           "does not flag). Baseline covers all dispositions and entities for "
                           "that severity.")
            except (TypeError, ValueError):
                st.write(ev)
        elif det == "no_escalation":
            st.markdown(f"Method: **{meta.get('method')}** — no statistical baseline involved.")
            show_table(pd.DataFrame(dict(condition=[
                "severity == critical", "disposition == true_positive",
                "escalated == false", "closed_at (context, not part of the condition)"],
                value=["true", "true", "gap", str(ev.get("closed_at", "—"))])), hide_index=True)
        elif det == "low_coverage":
            st.markdown(f"Method: **{meta.get('method')}**")
            try:
                obs = float(ev.get("observed_count"))
                med = float(ev.get("peer_median"))
                show_table(pd.DataFrame(dict(quantity=[
                    "Observed 30-day alert count", "Peer-group median (critical assets)",
                    "Threshold (25% of median)", "Window (days)",
                    "Reference window end", "Peer group"],
                    value=[f"{obs:.0f}", f"{med:.0f}", f"{0.25 * med:.1f}",
                           str(ev.get("window_days", 30)), str(ev.get("reference", ev.get("reference_end", "—"))),
                           str(ev.get("peer_group", "—"))])), hide_index=True)
                st.caption("A peer median of zero cannot produce a flag.")
            except (TypeError, ValueError):
                st.write(ev)
        else:
            st.write(ev)

    with st.expander("Evidence — attached source rows"):
        rows = ev.get("source_rows") or []
        st.caption("Each flag carries the original submitted record(s) — report-to-record "
                   "drill-down without reconstructing from a separate analytics database.")
        if rows:
            show_table(pd.DataFrame(rows), hide_index=True)
        else:
            st.caption("No source rows attached to this flag.")
        aids = ev.get("alert_ids") or []
        if aids:
            st.caption(f"Linked alerts: {', '.join(map(str, aids))}")
        if ev.get("asset_id"):
            st.caption(f"Linked asset: {ev.get('asset_id')}")

    with st.expander("Peer context"):
        if det == "fast_closure":
            try:
                bar_chart(pd.Series({
                    "Observed closure": float(ev.get("time_to_close_minutes")),
                    "Baseline Q1": float(ev.get("baseline_q1_minutes")),
                    "Lower fence": float(ev.get("baseline_q1_minutes")) - 1.5 * float(ev.get("baseline_iqr_minutes")),
                }))
                st.caption("Observed value vs the severity baseline (minutes).")
            except (TypeError, ValueError):
                st.caption("Baseline values unavailable.")
        elif det == "low_coverage":
            try:
                bar_chart(pd.Series({
                    "Observed count": float(ev.get("observed_count")),
                    "Peer median": float(ev.get("peer_median")),
                    "Threshold": 0.25 * float(ev.get("peer_median")),
                }))
                st.caption("Observed 30-day count vs the peer cohort.")
            except (TypeError, ValueError):
                st.caption("Peer statistics unavailable.")
        else:
            st.caption("D2 is deterministic — peer distributions do not apply.")
            n_all = sum(1 for x in load_flags(run_dir)
                        if x.get("detector") == "no_escalation")
            n_e = sum(1 for x in load_flags(run_dir)
                      if x.get("detector") == "no_escalation"
                      and x.get("entity_id") == f.get("entity_id"))
            st.metric("D2 findings · this entity", n_e, help=f"portfolio-wide: {n_all}")

    with st.expander("History — prior cycles"):
        cycles = _finding_cycles(f.get("entity_id"), finding_key(f))
        if len(cycles) <= 1:
            st.caption("No prior-cycle history — first cycle this detector fired for this "
                       "entity/key.")
        else:
            st.markdown("Fired in cycles: " + " · ".join(f"`{c}`" for c in cycles))

    st.divider()
    st.markdown("#### Disposition — the audit trail")
    entries = [e for e in load_dispositions(run_dir) if e.get("finding_id") == fid]
    if entries:
        with st.expander(f"Disposition log — {len(entries)} "
                         f"entr{'y' if len(entries) == 1 else 'ies'} (append-only)"):
            edf = pd.DataFrame(list(reversed(entries)))
            cols = [c for c in ["ts", "examiner", "disposition", "note"] if c in edf.columns]
            show_table(edf[cols] if cols else edf, hide_index=True)
    last = entries[-1].get("disposition") if entries else None
    idx = DISP_OPTIONS.index(last) if last in DISP_OPTIONS else 0
    choice = st.radio("Disposition", DISP_OPTIONS, index=idx, horizontal=True, key=f"dr_{fid}")
    note = st.text_area("Examiner note", value=(entries[-1].get("note", "") if entries else ""),
                        key=f"dn_{fid}")
    c1, c2 = st.columns([1, 2])
    if c1.button("Save disposition", type="primary", key=f"ds_{fid}"):
        append_disposition(run_dir, dict(
            ts=now_iso(), examiner=ss.get("examiner_name", "unknown"), finding_id=fid,
            entity_id=f.get("entity_id"), disposition=choice, note=note))
        st.toast("Disposition saved to the immutable log (results/dispositions.jsonl)")
        st.rerun()
    if c2.button("Add to review queue", key=f"dq_{fid}"):
        ok, msg = add_finding_to_queue(run_dir, f)
        if ok:
            st.toast(msg)
        else:
            st.info(msg)
    st.caption("This log is what the supervisor stands on months later when a CSE disputes "
               "a finding. Six months from now, this entry — timestamped and "
               "examiner-attributed — is the audit trail.")


if hasattr(st, "dialog"):
    @st.dialog("Finding detail")
    def finding_dialog(f: dict, run_dir: str):
        render_finding_detail(f, run_dir)
else:  # very old streamlit fallback: render inline
    def finding_dialog(f: dict, run_dir: str):
        render_finding_detail(f, run_dir)


# ----------------------------------------------------------------------------- router
PAGE_FUNCS = {
    "run": render_run_page,
    "portfolio": render_portfolio,
    "entity": render_entity_page,
    "findings": render_findings_page,
    "benchmark": render_benchmark_page,
    "queue": render_queue_page,
    "health": render_health_page,
    "detectors": render_detectors_page,
    "reports": render_reports_page,
}


def main():
    render_sidebar()
    rd = current_run_dir()
    with st.container():
        c1, c2 = st.columns([1, 8])
        with c1:
            if ss.get("nav_history"):
                if st.button("← Back", help="Breadcrumb-aware back navigation"):
                    go_back()
        label = PAGES.get(ss.nav_page, "")
        if ss.nav_page == "entity" and ss.get("active_entity_id"):
            label += f" · {ss.active_entity_id}"
        trail = [PAGES.get(h["page"], "") for h in (ss.get("nav_history") or [])[-3:]] + [label]
        with c2:
            st.caption("  ›  ".join(t for t in trail if t))
    maybe_show_search()
    if ss.nav_page == "run":
        render_run_page()
    elif ss.nav_page == "how":
        render_how_page(rd)
    elif ss.nav_page == "detectors":
        render_detectors_page(str(rd) if rd else None)
    elif rd is None:
        st.info("No assessment runs yet. Create one first — synthetic presets or a five-CSV "
                "submission.")
        if st.button("Go to Run assessment"):
            go("run")
    else:
        PAGE_FUNCS[ss.nav_page](str(rd))
    maybe_open_finding(rd)
    st.divider()
    st.caption("SAT-SA demonstration layer · offline & periodic · findings are advisory "
               "prioritisation signals, not enforcement outcomes · no real-time monitoring.")


main()
