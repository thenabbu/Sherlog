"""
SAT-SA Console — Streamlit front-end for the SAT-SA supervisory analytics CLI
=============================================================================

Supervisory Analytics Tool for SOC Assessment (SAT-SA) v0.1.0

A single-page console with tabbed navigation that drives the installed
`satsa` command-line tool through its full operational workflow and
visualises every artifact it produces:

    generate-synth -> ingest -> detect -> score -> report -> validate

Every action is executed by the real CLI (nothing is re-implemented here),
so the demo is faithful to the tool's contract: bounded-memory streaming,
Pydantic row validation with a rejects audit, evidence-attached flags,
peer benchmarking, and ground-truth validation.

Quick start
-----------
    pip install -e .                # provides the `satsa` entry point
    streamlit run streamlit_app.py

CLI location resolution order:
    1. `SATSA_CMD` environment variable
    2. `satsa` on PATH
    3. .venv/Scripts/satsa.exe (or .venv/bin/satsa) next to this file
    4. `python -c "from sat_sa.cli import app; app()"`
"""

from __future__ import annotations

import html as html_lib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

try:
    import pyarrow.parquet as pq
except Exception:  # pragma: no cover
    pq = None

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
APP_ROOT = Path(__file__).resolve().parent
RUNS_DIR = Path(os.environ.get("SATSA_RUNS_DIR", APP_ROOT / "runs"))
RUNS_DIR.mkdir(parents=True, exist_ok=True)

TABLES = ["entities", "assets", "alerts", "cases", "escalations"]

PAGES = [
    "Overview",
    "1 · Generate",
    "2 · Ingest",
    "3 · Detect",
    "4 · Score",
    "5 · Explorer",
    "6 · Validate",
]

DET_LABEL = {
    "fast_closure": "D1 — Fast-closure execution gap",
    "no_escalation": "D2 — Critical true-positive without escalation",
    "low_coverage": "D3 — Low critical-asset coverage",
}
DET_SHORT = {
    "fast_closure": "D1 fast closure",
    "no_escalation": "D2 no escalation",
    "low_coverage": "D3 low coverage",
}
DET_ACCENT = {
    "fast_closure": "#3f8fca",
    "no_escalation": "#d97706",
    "low_coverage": "#7c3aed",
}

PRESETS = {
    "Quick Demo · 8 CSEs × 50 alerts": {
        "entities": 8, "alerts_per_entity": 50, "seed": 7, "anomaly_rate": 0.25,
        "blurb": ("The specification's validation profile — finishes in seconds and is "
                  "expected to recover every injected signal (P/R/F1 = 1.000)."),
        "eta": "seconds",
    },
    "Medium · 25 × 400 (10K alerts)": {
        "entities": 25, "alerts_per_entity": 400, "seed": 42, "anomaly_rate": 0.15,
        "blurb": ("CLI defaults — 25 CSEs, ~10,000 alerts. A realistic small "
                  "supervisory cycle."),
        "eta": "~15–30 s",
    },
    "Large · 40 × 50K (2M alerts)": {
        "entities": 40, "alerts_per_entity": 50_000, "seed": 42, "anomaly_rate": 0.15,
        "blurb": ("The reference stress profile — 2,000,000 alerts through CSV ingest and "
                  "two-pass detection with the adaptive runtime. Allow ~400 MB free disk."),
        "eta": "minutes",
    },
    "Gigantic · 60 × 100K (6M alerts)": {
        "entities": 60, "alerts_per_entity": 100_000, "seed": 42, "anomaly_rate": 0.15,
        "blurb": ("Multi-million-alert scale, fully disk-backed: batched generation, "
                  "row-group ingest, and memory-mapped detection. Allow ~1 GB free disk."),
        "eta": "5–20 min",
    },
}
PRESET_KEYS = list(PRESETS)
HEAVY_PRESETS = ("Large · 40 × 50K (2M alerts)", "Gigantic · 60 × 100K (6M alerts)")

_STATE_DEFAULTS = {
    "run_name": "demo",
    "nav": PAGES[0],
    "rt_batch": 0, "rt_workers": 0, "rt_adaptive": True, "rt_health": 4,
    "thr_k": 1.5, "thr_window": 30, "thr_pct": 0.25, "use_thresholds": False,
    "w_fast": 2, "w_noesc": 3, "w_low": 2, "use_weights": False,
    "det_groups": ["execution_gaps", "negative_space"],
    "preset": PRESET_KEYS[0],
    "oc_preset": PRESET_KEYS[0],
    "custom_entities": 25, "custom_ape": 400, "custom_seed": 42, "custom_ar": 0.15,
    "ingest_fmt": "csv", "ingest_input": "",
}

FLOW_DIAGRAM = """periodic CSV / JSON submissions
            |
            v
schema validation + rejects audit -----> rejects.json
            |
            v
normalized parquet tables
            |
            +--> pass 1: closure-duration baselines on temporary disk
            +--> pass 2: execution-gap findings and asset counters
            |                         |
            +-------------------------v
                    evidence-attached flags.json
                               |
                               v
               risk scoring / priority ranking / report / explain"""

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

COMMAND_NOTE = "Equivalent shell command, executed by the installed satsa CLI:"
EMPTY_NOTE = "No rows to display."

# --------------------------------------------------------------------------- #
# Page config + styling
# --------------------------------------------------------------------------- #
st.set_page_config(page_title="SAT-SA Console", layout="wide")

st.markdown(
    """
    <style>
      .hero{background:linear-gradient(120deg,#0b2545 0%,#133c63 55%,#14506e 100%);
            border-radius:14px;padding:18px 26px;color:#f2f6fa;margin-bottom:12px;
            box-shadow:0 4px 18px rgba(8,20,40,.30);}
      .hero .kicker{font-size:.70rem;letter-spacing:.22em;opacity:.75;font-weight:700;}
      .hero h1{font-size:1.55rem;margin:.16em 0 .10em;font-weight:800;}
      .hero p{font-size:.92rem;opacity:.92;margin:0;max-width:70em;}
      .pill{display:inline-block;padding:3px 12px;border-radius:999px;font-size:.78rem;
            font-weight:650;margin:2px 6px 2px 0;}
      .pill-done{background:rgba(31,138,90,.16);border:1px solid rgba(31,138,90,.55);}
      .pill-todo{background:rgba(130,130,130,.12);border:1px solid rgba(130,130,130,.4);opacity:.75;}
      .arrow{opacity:.45;margin-right:4px;}
      .card{border:1px solid rgba(127,127,127,.28);border-radius:12px;padding:14px 16px;
            background:rgba(127,127,127,.06);margin-bottom:10px;}
      .card h4{margin:0 0 4px;font-size:.98rem;}
      .card .muted{font-size:.85rem;opacity:.75;margin:2px 0 0;}
      .chip{display:inline-block;font-size:.75rem;border:1px solid rgba(127,127,127,.35);
            border-radius:8px;padding:2px 8px;margin:2px 6px 2px 0;
            background:rgba(127,127,127,.08);}
      div[data-testid="stHorizontalRadio"]{
            border:1px solid rgba(127,127,127,.25);border-radius:10px;
            padding:5px 8px;background:rgba(127,127,127,.06);}
    </style>
    """,
    unsafe_allow_html=True,
)

HERO = """
<div class="hero">
  <div class="kicker">SUPERVISORY ANALYTICS · LOCAL · AUDITABLE · OFFLINE</div>
  <h1>SAT-SA Console</h1>
  <p>Triage which Critical Sector Entity, asset, alert, or process merits manual
     inspection — every finding carries its evidence. This console drives the installed
     <code style="background:rgba(255,255,255,.14);border-radius:4px;padding:0 6px;">satsa</code>
     CLI through the full supervisory cycle.</p>
</div>
"""

for _k, _v in _STATE_DEFAULTS.items():
    st.session_state.setdefault(_k, _v)

# --------------------------------------------------------------------------- #
# Session-state callbacks (safe widget mutation: run before instantiation)
# --------------------------------------------------------------------------- #
def set_nav(page: str):
    st.session_state.nav = page


def new_run_label():
    st.session_state.run_name = f"run-{datetime.now():%Y%m%d-%H%M%S}"


def nav_button(label: str, page: str, **kwargs):
    return st.button(label, on_click=set_nav, args=(page,), **kwargs)


def ensure_choice(key: str, options, default):
    """Drop stale widget state (e.g. from an older app version or another run)."""
    if st.session_state.get(key) not in options:
        st.session_state[key] = default

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def fmt_int(x) -> str:
    try:
        return f"{int(x):,}"
    except Exception:
        return "—"


def human_size_num(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024.0
    return f"{n:,.1f} TB"


def human_size(p: Path) -> str:
    try:
        return human_size_num(p.stat().st_size)
    except OSError:
        return "—"


def g(d, *keys, default="—"):
    for k in keys:
        if isinstance(d, dict) and d.get(k) is not None:
            return d[k]
    return default


def page_title(title: str, desc: str):
    st.markdown(f"### {title}")
    st.caption(desc)


def show_df(df, height=None):
    """Dataframe renderer that never passes an invalid height to st.dataframe."""
    if df is None or len(df) == 0:
        st.caption(EMPTY_NOTE)
        return
    if height is None:
        try:
            st.dataframe(df, hide_index=True)
        except TypeError:
            st.dataframe(df)
    else:
        try:
            st.dataframe(df, hide_index=True, height=height)
        except TypeError:
            st.dataframe(df, height=height)

# --------------------------------------------------------------------------- #
# Run paths (session-scoped)
# --------------------------------------------------------------------------- #
def safe_run_label() -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(st.session_state.run_name).strip()).strip("-")
    return s[:48] or "run"


def run_root() -> Path: return RUNS_DIR / safe_run_label()
def synth_dir() -> Path: return run_root() / "synth"
def norm_dir() -> Path: return run_root() / "normalized"
def results_dir() -> Path: return run_root() / "results"
def flags_path() -> Path: return results_dir() / "flags.json"
def scores_path() -> Path: return results_dir() / "entity_scores.csv"
def report_path() -> Path: return results_dir() / "report.json"
def config_path() -> Path: return run_root() / "detector_config.yaml"


def gt_path() -> Path:
    for n in ("ground_truth.parquet", "ground_truth.csv"):
        p = synth_dir() / n
        if p.exists():
            return p
    return synth_dir() / "ground_truth.parquet"


def stage_status() -> dict:
    return {
        "synth": (synth_dir() / "alerts.parquet").exists() and gt_path().exists(),
        "ingest": (norm_dir() / "alerts.parquet").exists(),
        "detect": flags_path().exists(),
        "score": scores_path().exists(),
        "report": report_path().exists(),
    }


def render_pipeline_strip():
    s = stage_status()
    items = [("1 Generate", "synth"), ("2 Ingest", "ingest"), ("3 Detect", "detect"),
             ("4 Score", "score"), ("5 Report", "report")]
    parts = []
    for i, (label, key) in enumerate(items):
        cls = "pill-done" if s[key] else "pill-todo"
        mark = "✓" if s[key] else "•"
        parts.append(f'<span class="pill {cls}">{label} {mark}</span>')
        if i < len(items) - 1:
            parts.append('<span class="arrow">→</span>')
    st.markdown('<div style="margin-bottom:6px">' + "".join(parts) + "</div>",
                unsafe_allow_html=True)

# --------------------------------------------------------------------------- #
# CLI backend
# --------------------------------------------------------------------------- #
def _popen_flags() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


@st.cache_resource(show_spinner="Locating the satsa CLI …")
def satsa_command():
    """Locate a working `satsa` invocation."""
    candidates: list[list[str]] = []
    override = os.environ.get("SATSA_CMD")
    if override:
        candidates.append(shlex.split(override, posix=(os.name != "nt")))
    exe = shutil.which("satsa")
    if exe:
        candidates.append([exe])
    for rel in ("Scripts/satsa.exe", "bin/satsa"):
        p = APP_ROOT / ".venv" / rel
        if p.exists():
            candidates.append([str(p)])
    candidates.append([sys.executable, "-c", "from sat_sa.cli import app; app()"])
    for cmd in candidates:
        try:
            probe = subprocess.run(cmd + ["--help"], capture_output=True,
                                   timeout=40, **_popen_flags())
            if probe.returncode == 0:
                return cmd
        except Exception:
            continue
    return None


class _Panel:
    """Live output panel — prefers st.status, degrades to plain placeholders."""

    def __init__(self, title: str):
        self._ok = hasattr(st, "status")
        if self._ok:
            self._st = st.status(title, expanded=True)
            self._body = self._st.empty()
        else:
            self._label = st.empty()
            self._label.markdown(f"**{title}**")
            self._body = st.empty()

    def code(self, text: str):
        try:
            self._body.code(text, language=None)
        except TypeError:
            self._body.code(text)

    def done(self, label: str):
        if self._ok:
            self._st.update(label=label, state="complete", expanded=False)
        else:
            self._label.markdown(f"Done — {label}")

    def fail(self, label: str):
        if self._ok:
            self._st.update(label=label, state="error", expanded=True)
        else:
            self._label.markdown(f"Failed — {label}")


def run_cli(args, title: str | None = None, ok_codes=(0,), tail=14,
            show_full_log=True):
    """Run a satsa CLI command, streaming its console output live."""
    cmd = satsa_command()
    if cmd is None:
        st.error("The `satsa` CLI could not be located — see the setup banner at the top.")
        return 127, ""
    full_cmd = cmd + [str(a) for a in args]
    cmd_name = str(args[0]) if args else "satsa"
    panel = _Panel(title or f"satsa {cmd_name}")
    lines: list[str] = []
    last = 0.0
    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUNBUFFERED", "1")
    try:
        proc = subprocess.Popen(
            full_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            cwd=str(APP_ROOT), env=env, **_popen_flags(),
        )
        for raw in proc.stdout:
            lines.append(raw.rstrip("\n"))
            now = time.time()
            if now - last > 0.2:
                panel.code("\n".join(lines[-tail:]) or "…")
                last = now
        rc = proc.wait()
    except Exception as e:
        panel.fail(f"`satsa {cmd_name}` could not be launched: {e}")
        return 1, "\n".join(lines)
    panel.code("\n".join(lines[-tail:]))
    log = "\n".join(lines)
    if rc in ok_codes:
        panel.done(f"`satsa {cmd_name}` finished — exit code {rc}")
    else:
        panel.fail(f"`satsa {cmd_name}` failed — exit code {rc}. Expand for the console output.")
    if show_full_log and lines:
        with st.expander(f"Full log — `satsa {cmd_name}` ({len(lines):,} lines)", expanded=False):
            st.code(log, language=None)
    return rc, log


def cli_snippet(args) -> str:
    parts = []
    for a in args:
        a = str(a)
        parts.append(f'"{a}"' if (" " in a or "\\" in a) else a)
    return "satsa " + " ".join(parts)


def show_cli(args):
    st.caption(COMMAND_NOTE)
    st.code(cli_snippet(args), language="powershell")

# --------------------------------------------------------------------------- #
# Artifact readers (cached by file mtime)
# --------------------------------------------------------------------------- #
@st.cache_data(show_spinner=False)
def parquet_info(path_str: str, mtime: float):
    if pq is None:
        return None
    try:
        md = pq.ParquetFile(path_str).metadata
        return {"rows": md.num_rows, "row_groups": md.num_row_groups}
    except Exception:
        return None


def pinfo(p: Path):
    if not p.exists():
        return None
    return parquet_info(str(p), p.stat().st_mtime)


@st.cache_data(show_spinner=False)
def preview_table(path_str: str, mtime: float, n: int = 8):
    if path_str.endswith(".parquet") and pq is not None:
        try:
            pf = pq.ParquetFile(path_str)
            batch = next(pf.iter_batches(batch_size=n))
            return batch.to_pandas()
        except Exception:
            pass
    try:
        return pd.read_csv(path_str, nrows=n)
    except Exception:
        return None


def preview_frame(p: Path, n: int = 8):
    if not p.exists():
        return None
    return preview_table(str(p), p.stat().st_mtime, n)


def load_flags() -> list:
    p = flags_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def load_scores():
    p = scores_path()
    if not p.exists():
        return None
    try:
        return pd.read_csv(p)
    except Exception:
        return None


def load_report():
    p = report_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_rejects() -> list:
    p = norm_dir() / "rejects.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def load_ground_truth_df():
    p = gt_path()
    if not p.exists():
        return None
    try:
        if p.suffix == ".parquet" and pq is not None:
            return pq.read_table(str(p)).to_pandas()
        return pd.read_csv(p)
    except Exception:
        return None


def parse_flag_counts(row) -> dict:
    raw = row.get("flag_count_by_detector") if row is not None else None
    if isinstance(raw, dict):
        return raw
    if raw is None:
        return {}
    try:
        return json.loads(str(raw))
    except Exception:
        return {}

# --------------------------------------------------------------------------- #
# Command builders (mirror the CLI contract exactly)
# --------------------------------------------------------------------------- #
def _rt(workers: bool = False) -> list:
    args = ["--batch-size", str(int(st.session_state.rt_batch))]
    if workers:
        args += ["--workers", str(int(st.session_state.rt_workers))]
    args += ["--healthcheck-interval", str(int(st.session_state.rt_health))]
    args += ["--adaptive" if st.session_state.rt_adaptive else "--no-adaptive"]
    return args


def build_generate_args(p: dict) -> list:
    return (["generate-synth",
             "--entities", str(p["entities"]),
             "--alerts-per-entity", str(p["alerts_per_entity"]),
             "--seed", str(p["seed"]),
             "--anomaly-rate", str(p["anomaly_rate"])]
            + _rt()
            + ["--out", str(synth_dir())])


def build_ingest_args(fmt: str = "csv", src: Path | None = None) -> list:
    return (["ingest", "--input", str(src or synth_dir()), "--format", fmt]
            + _rt(workers=True)
            + ["--out", str(norm_dir())])


def write_detector_config() -> Path:
    lines = ["# detector_config.yaml — generated by the SAT-SA Console",
             "# Values mirror the CLI's documented defaults unless changed in the UI."]
    if st.session_state.use_thresholds:
        lines += ["", "# Detector thresholds",
                  f"fast_closure_k: {st.session_state.thr_k}",
                  f"coverage_window_days: {int(st.session_state.thr_window)}",
                  f"coverage_threshold_pct: {st.session_state.thr_pct}"]
    if st.session_state.use_weights:
        lines += ["", "# Scoring weights", "weights:",
                  f"  fast_closure: {int(st.session_state.w_fast)}",
                  f"  no_escalation: {int(st.session_state.w_noesc)}",
                  f"  low_coverage: {int(st.session_state.w_low)}"]
    run_root().mkdir(parents=True, exist_ok=True)
    config_path().write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return config_path()


def build_detect_args() -> list:
    groups = ",".join(st.session_state.det_groups) or "execution_gaps,negative_space"
    args = ["detect", "--data", str(norm_dir()), "--detectors", groups]
    if st.session_state.use_thresholds:
        args += ["--config", str(write_detector_config())]
    args += _rt(workers=True)
    args += ["--out", str(flags_path())]
    return args


def build_score_args() -> list:
    args = ["score", "--flags", str(flags_path())]
    if st.session_state.use_weights:
        args += ["--config", str(write_detector_config())]
    return args + ["--out", str(scores_path())]


def build_report_args() -> list:
    return ["report", "--scores", str(scores_path()), "--flags", str(flags_path()),
            "--format", "table", "--out", str(report_path())]


def build_validate_args() -> list:
    return ["validate", "--flags", str(flags_path()),
            "--synth-ground-truth", str(gt_path())]

# --------------------------------------------------------------------------- #
# Shared UI components
# --------------------------------------------------------------------------- #
def runtime_expander(show_workers: bool = False):
    with st.expander("Runtime policy — streaming batches and the adaptive controller"):
        c1, c2, c3 = st.columns(3)
        c1.number_input("Initial batch size (0 = automatic)", 0, 5_000_000,
                        key="rt_batch",
                        help="Automatic selects 10,000–200,000 rows based on available RAM.")
        if show_workers:
            c2.number_input("Validation workers (0 = automatic)", 0, 64,
                            key="rt_workers",
                            help="Automatic: min(12, max(2, logical CPUs − 2)).")
        c3.number_input("Health-check interval (batches)", 1, 100, key="rt_health",
                        help="Completed batches between adaptive health checks.")
        st.checkbox("Adaptive mode — resize batches and workers from RAM and CPU health "
                    "checks; high CPU alone never triggers backoff",
                    key="rt_adaptive")


def det_card(col, title: str, purpose: str, formula: str, accent: str):
    col.markdown(
        f'<div class="card" style="border-left:4px solid {accent};"><h4>{title}</h4>'
        f'<p class="muted">{purpose}</p>'
        f'<p class="muted"><code>{formula}</code></p></div>',
        unsafe_allow_html=True)


def ev_get(ev: dict, *keys, default="—"):
    for k in keys:
        if k in ev and ev[k] is not None:
            return ev[k]
    return default


def render_flag_card(f: dict):
    det = str(f.get("detector"))
    ev = f.get("evidence") or {}
    accent = DET_ACCENT.get(det, "#888")

    def chip(label, *keys):
        v = ev_get(ev, *keys)
        return f'<span class="chip">{label}: <b>{html_lib.escape(str(v))}</b></span>'

    if det == "fast_closure":
        chips = [chip("observed", "observed_value"),
                 chip("baseline", "baseline_value"),
                 chip("baseline source", "baseline_source")]
    elif det == "no_escalation":
        chips = [chip("disposition", "disposition"),
                 chip("escalated", "escalated"),
                 chip("closed_at", "closed_at")]
    else:
        chips = [chip("alerts in window", "observed_count", "observed_alert_count",
                      "count", "alert_count"),
                 chip("peer median", "peer_median"),
                 chip("window (days)", "window_days"),
                 chip("peer group", "peer_group")]

    st.markdown(
        f'<div class="card" style="border-left:4px solid {accent}">'
        f'<div style="font-weight:700">{html_lib.escape(str(f.get("flag_id")))} · '
        f'{DET_LABEL.get(det, det)}</div>'
        f'<div style="margin-top:4px">{html_lib.escape(str(f.get("rationale") or ""))}</div>'
        f'<div style="margin-top:8px">{" ".join(chips)}</div></div>',
        unsafe_allow_html=True)
    with st.expander(f"Full flag JSON — {f.get('flag_id')} (including source rows)"):
        st.json(f)


def flags_frame(flags: list) -> pd.DataFrame:
    rows = []
    for f in flags:
        rows.append({
            "flag_id": f.get("flag_id"),
            "detector": DET_SHORT.get(f.get("detector"), f.get("detector")),
            "entity_id": f.get("entity_id"),
            "rationale": (f.get("rationale") or "")[:120],
        })
    return pd.DataFrame(rows)


def _reason_text(reasons) -> str:
    parts = []
    if isinstance(reasons, list):
        for rr in reasons:
            if isinstance(rr, dict):
                loc = ".".join(str(x) for x in (rr.get("loc") or [])) or "?"
                parts.append(f"{loc}: {rr.get('msg', '')}")
            else:
                parts.append(str(rr))
    elif reasons:
        parts.append(str(reasons))
    return "; ".join(parts) or "—"


def rejects_frame(rejects: list) -> pd.DataFrame:
    rows = []
    for r in rejects[:1000]:
        rec = r.get("record") or {}
        rid = next((rec.get(k) for k in ("alert_id", "entity_id", "asset_id",
                                         "case_id", "escalation_id")
                    if rec.get(k) is not None), "—")
        rows.append({"source": r.get("source"), "table": r.get("table"),
                     "row": r.get("row"), "record_id": rid,
                     "reason": _reason_text(r.get("reason"))})
    return pd.DataFrame(rows)


def parse_system_info(log: str):
    txt = ANSI_RE.sub("", log or "").strip()
    try:
        return json.loads(txt)
    except Exception:
        m = re.search(r"\{.*\}", txt, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def render_sysinfo(info: dict):
    c = st.columns(4)
    c[0].metric("Logical CPUs", fmt_int(g(info, "logical_cpus", "cpus")))
    tot = g(info, "total_memory_mb", "total_mb", default=None)
    av = g(info, "available_memory_mb", "available_mb", default=None)
    c[1].metric("Total RAM", f"{float(tot):,.0f} MB" if isinstance(tot, (int, float)) else "—")
    c[2].metric("Available RAM", f"{float(av):,.0f} MB" if isinstance(av, (int, float)) else "—")
    c[3].metric("Platform", g(info, "platform"))
    st.caption(f"Requested policy → initial batch size **{g(info, 'batch_size', 'selected_batch_size')}** "
               f"rows, **{g(info, 'workers', 'selected_workers')}** workers.")

# --------------------------------------------------------------------------- #
# Ground-truth metrics (computed from artifacts, mirrors the CLI semantics)
# --------------------------------------------------------------------------- #
def _norm_detector(v) -> str:
    v = str(v).strip().lower()
    if v in ("d1", "1", "fast_closure") or "fast" in v or "closure" in v:
        return "fast_closure"
    if v in ("d2", "2", "no_escalation") or "escalat" in v:
        return "no_escalation"
    if v in ("d3", "3", "low_coverage") or "coverage" in v or "negative" in v:
        return "low_coverage"
    return v


def compute_validation_metrics():
    flags = load_flags()
    gt = load_ground_truth_df()
    if gt is None or len(gt) == 0 or not flags:
        return None
    det_col = next((c for c in gt.columns
                    if c.lower() in ("detector", "type", "anomaly_type", "injection_type",
                                     "signal", "flag_type", "anomaly", "kind")), None)
    if det_col is None:
        return None
    expected = {k: set() for k in DET_LABEL}
    for _, r in gt.iterrows():
        d = _norm_detector(r[det_col])
        if d not in expected:
            continue
        if d == "low_coverage":
            key = (str(r.get("entity_id")), str(r.get("asset_id")))
        else:
            key = (str(r.get("entity_id")), str(r.get("alert_id")))
        expected[d].add(key)
    predicted = {k: set() for k in DET_LABEL}
    for f in flags:
        d = str(f.get("detector"))
        if d not in predicted:
            continue
        ev = f.get("evidence") or {}
        if d == "low_coverage":
            aid = ev.get("asset_id")
            if aid is None:
                aids = ev.get("asset_ids") or []
                aid = aids[0] if aids else None
            if aid:
                predicted[d].add((str(f.get("entity_id")), str(aid)))
        else:
            for aid in ev.get("alert_ids") or []:
                predicted[d].add((str(f.get("entity_id")), str(aid)))
    out = []
    for d in ("fast_closure", "no_escalation", "low_coverage"):
        exp, pred = expected[d], predicted[d]
        tp = len(exp & pred)
        prec = tp / len(pred) if pred else 0.0
        rec = tp / len(exp) if exp else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        out.append({"detector": DET_LABEL[d], "short": DET_SHORT[d],
                    "injected": len(exp), "detected": len(pred), "tp": tp,
                    "fp": len(pred) - tp, "fn": len(exp) - tp,
                    "precision": prec, "recall": rec, "f1": f1})
    return out

# --------------------------------------------------------------------------- #
# Full pipeline (one-click demo)
# --------------------------------------------------------------------------- #
def render_snapshot():
    s = stage_status()
    flags = load_flags() if s["detect"] else []
    scores = load_scores()
    met = compute_validation_metrics() if flags else None
    info = pinfo(norm_dir() / "alerts.parquet") or {}
    top = "—"
    if scores is not None and len(scores) and "risk_score" in scores.columns:
        r0 = scores.iloc[0]
        top = f"{r0['entity_id']} ({float(r0['risk_score']):.4f})"
    f1 = "—"
    if met:
        vals = [m["f1"] for m in met if m["injected"]]
        f1 = f"{sum(vals) / len(vals):.3f}" if vals else "—"
    m = st.columns(4)
    m[0].metric("Alerts normalized", fmt_int(info.get("rows")))
    m[1].metric("Flags raised", fmt_int(len(flags)))
    m[2].metric("Top-risk entity", top)
    m[3].metric("Mean F1 vs ground truth", f1)


def run_full_pipeline():
    preset_label = st.session_state.oc_preset
    p = PRESETS[preset_label]
    st.markdown(f"Running the full cycle for **{preset_label}** — every step below is the "
                f"real CLI at work, leaving auditable artifacts on disk.")
    prog = st.progress(0.0)
    cap = st.empty()
    steps = [
        ("generate-synth", build_generate_args(p)),
        ("ingest", build_ingest_args("csv")),
        ("detect", build_detect_args()),
        ("score", build_score_args()),
        ("report", build_report_args()),
        ("validate", build_validate_args()),
    ]
    for i, (name, args) in enumerate(steps):
        cap.markdown(f"**Step {i + 1} of 6 — satsa {name}**")
        rc, _ = run_cli(args, title=f"satsa {name}", show_full_log=False)
        prog.progress((i + 1) / len(steps))
        if rc not in (0, 1):
            prog.empty()
            cap.empty()
            st.error(f"Pipeline stopped at `{name}` (exit code {rc}). "
                     f"Expand the panel above for the console output.")
            return
    prog.empty()
    cap.empty()
    st.success("Full pipeline complete — synthetic submission, normalized parquet, "
               "flags, scores, report, and validation are all on disk.")
    render_snapshot()
    b1, b2 = st.columns(2)
    nav_button("Open the entity explorer", PAGES[5], type="primary")
    # keep both buttons in their columns
    with b1:
        pass
    with b2:
        nav_button("See validation details", PAGES[6])

# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
def page_overview():
    page_title("Overview",
               "Supervisory analytics for Critical Sector Entities — generate a submission, "
               "normalize it, detect explainable signals, rank entities, and validate "
               "against ground truth. Everything runs through the installed satsa CLI.")

    s = stage_status()
    flags = load_flags() if s["detect"] else []
    scores = load_scores()
    n_alerts = None
    for pth in (norm_dir() / "alerts.parquet", synth_dir() / "alerts.parquet"):
        info = pinfo(pth)
        if info:
            n_alerts = info["rows"]
            break
    m = st.columns(4)
    m[0].metric("Pipeline stages complete", f"{sum(s.values())}/5")
    m[1].metric("Alerts processed", fmt_int(n_alerts) if n_alerts else "—")
    m[2].metric("Flags raised", fmt_int(len(flags)) if s["detect"] else "—")
    m[3].metric("Entities ranked", fmt_int(len(scores)) if scores is not None else "—")

    run_now = False
    left, right = st.columns([3, 2], gap="large")
    with left:
        st.subheader("One-click demonstration")
        st.markdown("Runs the **entire supervisory cycle** with the real CLI — "
                    "generate → ingest → detect → score → report → validate — and "
                    "leaves every artifact on disk for audit.")
        ensure_choice("oc_preset", PRESET_KEYS, PRESET_KEYS[0])
        st.selectbox("Dataset preset", PRESET_KEYS, key="oc_preset")
        p = PRESETS[st.session_state.oc_preset]
        st.caption(p["blurb"] + f"  ·  Estimated time: **{p['eta']}**.")
        heavy = st.session_state.oc_preset in HEAVY_PRESETS
        go = True
        if heavy:
            go = st.checkbox("I understand this is a multi-minute benchmark run",
                             value=False)
        if st.button("Run full pipeline", type="primary",
                     disabled=(heavy and not go)):
            run_now = True
        with st.expander("Suggested two-minute demonstration script"):
            st.markdown(
                "1. **Probe the host** — show the automatic batch-size and worker policy.\n"
                "2. **Run full pipeline** on *Quick Demo* — six CLI steps stream live.\n"
                "3. Open the **flag inspector** on the Detect tab — the evidence contract.\n"
                "4. Visit the **Explorer** tab — top-ranked CSE with rationale cards.\n"
                "5. Finish on **Validate** — precision, recall, and F1 vs ground truth.")
    with right:
        st.subheader("Host profile")
        if st.button("Probe system (satsa system-info)"):
            rc, log = run_cli(["system-info"], title="satsa system-info",
                              show_full_log=False)
            info = parse_system_info(log)
            if info:
                st.session_state.sysinfo = info
        info = st.session_state.get("sysinfo")
        if info:
            render_sysinfo(info)
        else:
            st.caption("Probes logical CPUs, total and available RAM, platform, and the "
                       "automatic batch-size and worker policy the runtime would select. "
                       "No telemetry leaves this host.")
    if run_now:
        st.divider()
        run_full_pipeline()

    st.divider()
    st.subheader("Built supervisory-grade")
    principles = [
        ("Local & offline", "No runtime network calls, no telemetry — air-gap deployable."),
        ("Bounded memory", "Millions of alerts stream through parquet row groups; "
                           "statistics stay disk-backed."),
        ("Rejects audit", "Every invalid row is preserved with source, row index, "
                          "values, and reason."),
        ("Evidence-first", "Each flag carries detector, measurements, baseline, "
                           "and source rows."),
    ]
    cols = st.columns(4)
    for col, (t, d) in zip(cols, principles):
        col.markdown(f'<div class="card"><h4>{t}</h4><p class="muted">{d}</p></div>',
                     unsafe_allow_html=True)

    with st.expander("Component flow (from the architecture specification)"):
        st.code(FLOW_DIAGRAM, language=None)
    with st.expander("Existing runs on this machine"):
        rows = []
        for d in sorted(RUNS_DIR.iterdir()):
            if d.is_dir():
                size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
                rows.append({"run": d.name, "artifacts": human_size_num(size),
                             "path": str(d)})
        if rows:
            show_df(pd.DataFrame(rows), height=220)
        else:
            st.caption("No runs yet — generate data on the Generate tab.")

    st.caption("Scope note: this is the CLI-only, local and offline MVP. The console is a "
               "thin visual layer — every number on screen comes from a `satsa` artifact.")


def current_generate_params() -> dict:
    if st.session_state.preset == "Custom":
        return {
            "entities": int(st.session_state.custom_entities),
            "alerts_per_entity": int(st.session_state.custom_ape),
            "seed": int(st.session_state.custom_seed),
            "anomaly_rate": float(st.session_state.custom_ar),
        }
    p = PRESETS[st.session_state.preset]
    return {k: p[k] for k in ("entities", "alerts_per_entity", "seed", "anomaly_rate")}


def page_generate():
    page_title("Step 1 — Generate a synthetic submission",
               "Deterministic, seeded, anomaly-injected data written in bounded batches — "
               "CSV and parquet side by side, plus ground truth reserved for validation.")

    ensure_choice("preset", PRESET_KEYS + ["Custom"], PRESET_KEYS[0])
    choice = st.selectbox("Dataset preset", PRESET_KEYS + ["Custom"], key="preset")
    if choice == "Custom":
        c1, c2 = st.columns(2)
        c1.number_input("Entities (CSEs) — minimum 4", 4, 500, key="custom_entities")
        c2.number_input("Alerts per entity — minimum 1", 1, 500_000, key="custom_ape")
        c3, c4 = st.columns(2)
        c3.number_input("Random seed", 0, 2**31 - 1, key="custom_seed")
        c4.slider("Anomaly rate (per anomaly type)", 0.01, 1.0, key="custom_ar",
                  step=0.01, format="%.2f")
        st.caption("Custom profile — the generator stays deterministic for the same "
                   "parameters and seed.")
    else:
        st.info(PRESETS[choice]["blurb"] +
                f"  ·  **Estimated time: {PRESETS[choice]['eta']}**")

    p = current_generate_params()
    inj = max(1, round(p["entities"] * p["anomaly_rate"]))
    total = p["entities"] * p["alerts_per_entity"] + 2 * inj
    m = st.columns(4)
    m[0].metric("Critical Sector Entities", fmt_int(p["entities"]))
    m[1].metric("Total alerts", fmt_int(total))
    m[2].metric("Injected anomalies per detector", fmt_int(inj))
    m[3].metric("Assets (2 critical + 1 high each)", fmt_int(p["entities"] * 3))
    st.caption("total alerts = entities × alerts_per_entity + 2 × max(1, round(entities × "
               "anomaly_rate)) — the two additions per selected entity are the fast-closure "
               "and no-escalation injections.")
    st.caption("Anomaly types: fast closure (D1) · critical true-positive without "
               "escalation (D2) · low critical-asset coverage (D3 — changes asset "
               "selection only).")

    runtime_expander(show_workers=False)
    heavy = total >= 1_000_000
    confirmed = (st.checkbox("I understand this is a multi-minute benchmark run",
                             value=False) if heavy else True)
    args = build_generate_args(p)
    show_cli(args)
    if st.button("Run generate-synth", type="primary", disabled=not confirmed):
        rc, _ = run_cli(args, title="satsa generate-synth")
        if rc == 0 and (synth_dir() / "alerts.parquet").exists():
            st.success(f"generate-synth completed — {fmt_int(total)} alerts across "
                       f"{fmt_int(p['entities'])} entities written to disk.")
        elif rc == 0:
            st.warning("Command finished but alerts.parquet was not found — check the log.")

    if stage_status()["synth"]:
        render_synth_summary()
        nav_button("Continue to step 2 — Ingest & validate", PAGES[2], type="primary")


def render_synth_summary():
    st.subheader("Generated artifacts")
    rows = []
    for t in TABLES:
        pp, cp = synth_dir() / f"{t}.parquet", synth_dir() / f"{t}.csv"
        info = pinfo(pp)
        rows.append({"table": t,
                     "rows": fmt_int(info["rows"]) if info else "—",
                     "row groups": fmt_int(info["row_groups"]) if info else "—",
                     "parquet size": human_size(pp) if pp.exists() else "—",
                     "csv size": human_size(cp) if cp.exists() else "—"})
    gt_df = load_ground_truth_df()
    rows.append({"table": "ground_truth",
                 "rows": fmt_int(len(gt_df)) if gt_df is not None else "—",
                 "row groups": "—",
                 "parquet size": human_size(synth_dir() / "ground_truth.parquet"),
                 "csv size": human_size(synth_dir() / "ground_truth.csv")})
    show_df(pd.DataFrame(rows))
    ainfo = pinfo(synth_dir() / "alerts.parquet")
    if ainfo:
        st.caption(f"Each generated batch became a parquet row group — "
                   f"**{fmt_int(ainfo['row_groups'])} row groups** — so detection can scan "
                   f"row groups later without loading the whole file.")
    t1, t2, t3, t4 = st.tabs(["Entities", "Assets", "Alerts (first rows)", "Ground truth"])
    with t1:
        show_df(preview_frame(synth_dir() / "entities.csv"))
    with t2:
        show_df(preview_frame(synth_dir() / "assets.csv"))
    with t3:
        show_df(preview_frame(synth_dir() / "alerts.csv"))
    with t4:
        show_df(gt_df if gt_df is not None else preview_frame(gt_path()))
        st.caption("Reserved for synthetic validation — deliberately ignored by ingestion.")


def page_ingest():
    page_title("Step 2 — Ingest & validate the submission",
               "Incremental CSV parsing, parallel Pydantic v2 row validation, a rejects "
               "audit trail, and normalized Snappy-parquet storage.")

    custom = str(st.session_state.get("ingest_input", "") or "").strip()
    if not stage_status()["synth"] and not custom:
        st.warning("No submission found for this run label — complete step 1 first "
                   "(or point the advanced input path at an external submission).")
        nav_button("Go to step 1 — Generate data", PAGES[1], type="primary")
        return

    with st.expander("Data contract — the five logical tables", expanded=False):
        st.markdown("Required fields are marked `*`. Unknown columns are ignored; blank "
                    "cells become null; chronology violations (e.g. `closed_at` before "
                    "`created_at`) are rejected and audited — never silently dropped.")
        contract = pd.DataFrame([
            ("entities", "entity_id*, name*, peer_group*, sector"),
            ("assets", "asset_id*, entity_id*, criticality*, asset_type"),
            ("alerts", "alert_id*, entity_id*, asset_id, category*, severity*, created_at*, "
                       "first_ack_at, closed_at, disposition*, escalated*, escalated_at, case_id"),
            ("cases", "case_id*, entity_id*, opened_at*, closed_at, alert_ids*, "
                      "root_cause_documented*"),
            ("escalations", "escalation_id*, alert_id*, escalated_at*, escalated_to_tier*"),
        ], columns=["table", "fields"])
        show_df(contract)

    c1, c2 = st.columns([1, 2])
    ensure_choice("ingest_fmt", ["csv", "json"], "csv")
    fmt = c1.selectbox("Input format", ["csv", "json"], key="ingest_fmt",
                       help="CSV is parsed and validated incrementally in batches; "
                            "JSON is loaded as one document.")
    with c2.expander("Advanced — custom input path"):
        st.text_input("Input file or directory (blank = this run's synth output)",
                      key="ingest_input")

    runtime_expander(show_workers=True)
    src = Path(custom) if custom else synth_dir()
    args = build_ingest_args(fmt, src)
    show_cli(args)
    if st.button("Run ingest", type="primary"):
        rc, _ = run_cli(args, title="satsa ingest")
        if rc == 0 and (norm_dir() / "alerts.parquet").exists():
            st.success("ingest completed — submission normalized to parquet with a "
                       "rejects audit.")

    if stage_status()["ingest"]:
        render_ingest_summary()
        nav_button("Continue to step 3 — Detect signals", PAGES[3], type="primary")


def render_ingest_summary():
    st.subheader("Normalized storage (Snappy parquet)")
    rows = []
    for t in TABLES:
        p = norm_dir() / f"{t}.parquet"
        info = pinfo(p)
        rows.append({"file": f"{t}.parquet",
                     "rows": fmt_int(info["rows"]) if info else "—",
                     "row groups": fmt_int(info["row_groups"]) if info else "—",
                     "size": human_size(p) if p.exists() else "—"})
    rejects = load_rejects()
    rp = norm_dir() / "rejects.json"
    rows.append({"file": "rejects.json", "rows": fmt_int(len(rejects)),
                 "row groups": "—", "size": human_size(rp) if rp.exists() else "—"})
    show_df(pd.DataFrame(rows))

    ainfo = pinfo(norm_dir() / "alerts.parquet")
    acc = ainfo["rows"] if ainfo else None
    m = st.columns(3)
    m[0].metric("Alert rows accepted", fmt_int(acc))
    m[1].metric("Rows rejected (audited)", fmt_int(len(rejects)))
    m[2].metric("Tables written",
                fmt_int(sum(1 for t in TABLES if (norm_dir() / f"{t}.parquet").exists())))
    if ainfo:
        st.caption(f"**{fmt_int(ainfo['row_groups'])} row groups** — every accepted CSV "
                   f"batch was appended as its own row group, preserving source order.")
    if rejects:
        st.warning(f"{fmt_int(len(rejects))} rows failed validation and were preserved in "
                   f"the rejects audit — malformed input never silently disappears.")
        show_df(rejects_frame(rejects), height=260)
        with st.expander("Raw rejects.json (first 3 entries)"):
            st.json(rejects[:3])
    else:
        st.success("0 rejects — every row in the submission passed Pydantic validation.")


def page_detect():
    page_title("Step 3 — Detect supervisory signals",
               "Two streaming passes over parquet row groups — disk-backed severity "
               "baselines, then per-batch detection — produce evidence-attached flags.")

    if not stage_status()["ingest"]:
        st.warning("Normalized data not found for this run label — complete step 2 first.")
        nav_button("Go to step 2 — Ingest & validate", PAGES[2], type="primary")
        return

    a, b, c = st.columns(3)
    det_card(a, "D1 — Fast-closure execution gap",
             "High- and critical-severity alerts closed implausibly fast compared with "
             "the submission-wide closure distribution for that severity.",
             "t_close &lt; Q1(severity) − k × IQR(severity)",
             DET_ACCENT["fast_closure"])
    det_card(b, "D2 — Critical true-positive without escalation",
             "Critical true-positive alerts that were closed without any recorded "
             "escalation.",
             "severity = critical ∧ disposition = true_positive ∧ escalated = false",
             DET_ACCENT["no_escalation"])
    det_card(c, "D3 — Low critical-asset coverage",
             "Critical assets generating unusually few alerts relative to their peer "
             "cohort — a possible monitoring gap (negative space).",
             "alerts_in_window &lt; threshold × peer median",
             DET_ACCENT["low_coverage"])

    st.markdown("**Detector groups** — `execution_gaps` ships D1 and D2; "
                "`negative_space` ships D3.")
    valid_groups = {"execution_gaps", "negative_space"}
    if not set(st.session_state.get("det_groups", [])) <= valid_groups:
        st.session_state.det_groups = ["execution_gaps", "negative_space"]
    st.multiselect("Groups to run", ["execution_gaps", "negative_space"],
                   key="det_groups")

    with st.expander("Thresholds — optional detector_config.yaml override"):
        st.checkbox("Override the documented defaults (k = 1.5, window = 30 days, "
                    "threshold = 0.25)", key="use_thresholds")
        if st.session_state.use_thresholds:
            t1, t2, t3 = st.columns(3)
            t1.slider("fast_closure_k", 0.5, 3.0, key="thr_k", step=0.05, format="%.2f")
            t2.slider("coverage_window_days", 7, 90, key="thr_window")
            t3.slider("coverage_threshold_pct", 0.05, 0.75, key="thr_pct",
                      step=0.01, format="%.2f")

    runtime_expander(show_workers=True)
    ok = bool(st.session_state.det_groups)
    if not ok:
        st.warning("Select at least one detector group.")
    args = build_detect_args()
    show_cli(args)
    if st.button("Run detect", type="primary", disabled=not ok):
        rc, _ = run_cli(args, title="satsa detect")
        if rc == 0 and flags_path().exists():
            st.success(f"detect completed — {fmt_int(len(load_flags()))} flags written "
                       f"to flags.json.")

    if stage_status()["detect"]:
        render_detect_summary()
        nav_button("Continue to step 4 — Score & report", PAGES[4], type="primary")


def render_detect_summary():
    flags = load_flags()
    st.subheader("Detection results")
    if not flags:
        st.info("flags.json is empty — no signal met the detector conditions for this run.")
        return
    det_counts: dict = {}
    ent_counts: dict = {}
    for f in flags:
        det_counts[f.get("detector", "?")] = det_counts.get(f.get("detector", "?"), 0) + 1
        ent_counts[f.get("entity_id", "?")] = ent_counts.get(f.get("entity_id", "?"), 0) + 1
    m = st.columns(4)
    m[0].metric("Total flags", fmt_int(len(flags)))
    m[1].metric("Fast closure (D1)", fmt_int(det_counts.get("fast_closure", 0)))
    m[2].metric("No escalation (D2)", fmt_int(det_counts.get("no_escalation", 0)))
    m[3].metric("Low coverage (D3)", fmt_int(det_counts.get("low_coverage", 0)))
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Flags by detector**")
        s = pd.Series({DET_SHORT.get(k, str(k)): v
                       for k, v in sorted(det_counts.items(), key=lambda kv: -kv[1])})
        st.bar_chart(s)
    with c2:
        st.markdown("**Top entities by flag count**")
        top = pd.Series(ent_counts).sort_values(ascending=False).head(10)
        st.bar_chart(top)
    st.markdown("**Flag ledger**")
    show_df(flags_frame(flags), height=260)
    st.markdown("**Flag inspector — the evidence contract**")
    ids = [f.get("flag_id") for f in flags][:2000]
    if len(flags) > len(ids):
        st.caption("Showing the first 2,000 flags in the selector; the ledger above "
                   "lists all of them.")
    ensure_choice("flag_sel", ids, ids[0])
    sel = st.selectbox("Flag ID", ids, key="flag_sel")
    flag = next((f for f in flags if f.get("flag_id") == sel), flags[0])
    st.caption("Every flag stands on its own: detector, entity, rationale, measurements, "
               "baseline, source rows, and generation time.")
    st.json(flag)
    if (results_dir() / "alert_volumes.json").exists():
        st.caption("detect also wrote alert_volumes.json next to flags.json — scoring "
                   "uses it to normalise by entity alert volume.")


def page_score():
    page_title("Step 4 — Score, rank & report",
               "Weighted flag counts normalised by alert volume produce a one-based "
               "priority ranking; the report bundles the full evidence trail.")

    if not stage_status()["detect"]:
        st.warning("No flags.json for this run label — complete step 3 first.")
        nav_button("Go to step 3 — Detect signals", PAGES[3], type="primary")
        return

    st.markdown(
        '<div class="card"><b>risk_score(e) = Σ weight(detector) × flags(e, detector) '
        '÷ log(1 + alert_volume(e))</b>'
        '<p class="muted">Default weights: fast_closure = 2, no_escalation = 3, '
        'low_coverage = 2. Ties break by distinct detectors triggered, then entity_id. '
        'Zero-volume entities skip the denominator correction.</p></div>',
        unsafe_allow_html=True)

    with st.expander("Scoring weights — optional YAML override"):
        st.checkbox("Override default weights (2 / 3 / 2)", key="use_weights")
        if st.session_state.use_weights:
            w1, w2, w3 = st.columns(3)
            w1.number_input("fast_closure", 0, 10, key="w_fast")
            w2.number_input("no_escalation", 0, 10, key="w_noesc")
            w3.number_input("low_coverage", 0, 10, key="w_low")

    col1, col2 = st.columns(2)
    score_args = build_score_args()
    with col1:
        show_cli(score_args)
        if st.button("Run score", type="primary"):
            rc, _ = run_cli(score_args, title="satsa score")
            if rc == 0 and scores_path().exists():
                st.success("score completed — entity_scores.csv written.")
    report_args = build_report_args()
    with col2:
        show_cli(report_args)
        if st.button("Run report", type="primary"):
            if not scores_path().exists():
                st.warning("Run scoring first — report needs entity_scores.csv.")
            else:
                rc, _ = run_cli(report_args, title="satsa report")
                if rc == 0 and report_path().exists():
                    st.success("report completed — report.json written.")

    render_score_summary()
    if stage_status()["score"]:
        nav_button("Continue to step 5 — Entity explorer", PAGES[5], type="primary")


def render_score_summary():
    scores = load_scores()
    if scores is None or len(scores) == 0:
        st.info("Run scoring to produce the priority ranking.")
        return
    st.subheader("Priority ranking")
    if "entity_id" in scores.columns and "risk_score" in scores.columns:
        st.markdown("**Top entities by risk score**")
        st.bar_chart(scores.head(15).set_index("entity_id")["risk_score"])
    view = scores.copy()
    if "risk_score" in view.columns:
        view["risk_score"] = view["risk_score"].map(lambda v: f"{float(v):.4f}")
    show_df(view, height=280)
    st.download_button("Download entity_scores.csv", data=scores_path().read_bytes(),
                       file_name="entity_scores.csv", mime="text/csv", key="dl_scores")

    rep = load_report()
    if rep is not None:
        summary = rep.get("summary") or {}
        st.subheader("Report summary")
        m = st.columns(4)
        m[0].metric("Entities analysed",
                    fmt_int(g(summary, "analysed_entity_count", "entities_analysed",
                              "entity_count", default=len(scores))))
        m[1].metric("Total flags",
                    fmt_int(g(summary, "total_flag_count", "total_flags",
                              default=len(load_flags()))))
        det = summary.get("detector_counts") or summary.get("flags_by_detector") or {}
        if isinstance(det, dict):
            for i, (k, v) in enumerate(det.items()):
                if i < 2:
                    m[2 + i].metric(DET_SHORT.get(k, str(k)), fmt_int(v))
        if report_path().exists():
            st.download_button("Download report.json", data=report_path().read_bytes(),
                               file_name="report.json", mime="application/json",
                               key="dl_report")


def page_explain():
    page_title("Step 5 — Entity explorer",
               "Per-entity drill-down of every finding with rationale and evidence — the "
               "same information `satsa explain` prints on the console.")

    flags = load_flags()
    scores = load_scores()
    if not flags:
        st.warning("No flags.json for this run label — complete step 3 first.")
        nav_button("Go to step 3 — Detect signals", PAGES[3], type="primary")
        return

    if scores is not None and "entity_id" in scores.columns and len(scores):
        options = list(scores["entity_id"])
    else:
        options = sorted({str(f.get("entity_id")) for f in flags})
    ensure_choice("expl_entity", options, options[0])
    eid = st.selectbox("Entity", options, key="expl_entity")
    my = [f for f in flags if str(f.get("entity_id")) == str(eid)]
    row = None
    if scores is not None and "entity_id" in scores.columns and (scores["entity_id"] == eid).any():
        row = scores[scores["entity_id"] == eid].iloc[0]

    m = st.columns(5)
    m[0].metric("Priority rank", fmt_int(row.get("priority_rank")) if row is not None else "—")
    m[1].metric("Risk score",
                f"{float(row['risk_score']):.4f}" if row is not None and "risk_score" in row else "—")
    m[2].metric("Flags", fmt_int(len(my)))
    m[3].metric("Detectors triggered",
                fmt_int(row.get("distinct_detectors_triggered")) if row is not None
                else fmt_int(len({f.get("detector") for f in my})))
    m[4].metric("Alert volume", fmt_int(row.get("alert_volume")) if row is not None else "—")
    counts = parse_flag_counts(row)
    if counts:
        chips = " ".join(f'<span class="chip">{DET_SHORT.get(k, str(k))}: <b>{v}</b></span>'
                         for k, v in counts.items())
        st.markdown(chips, unsafe_allow_html=True)

    st.subheader(f"Findings for {eid}")
    if not my:
        st.success("No findings for this entity — it passed all three detectors.")
    for f in my:
        render_flag_card(f)

    st.divider()
    if st.button(f"Run satsa explain for {eid}", key="btn_explain"):
        rc, _ = run_cli(["explain", "--entity-id", str(eid), "--flags", str(flags_path())],
                        title=f"satsa explain — {eid}", ok_codes=(0, 1),
                        show_full_log=False)
        if rc == 1:
            st.info("Exit code 1 — the CLI found no matching finding for this entity.")


def page_validate():
    page_title("Step 6 — Validate against ground truth",
               "Injected anomalies are the known truth. Validation asks: did the "
               "detectors recover them — precision, recall, and F1 per detector?")

    if not stage_status()["detect"]:
        st.warning("No flags.json for this run label — complete step 3 first.")
        nav_button("Go to step 3 — Detect signals", PAGES[3], type="primary")
        return
    if not gt_path().exists():
        st.warning("No ground_truth file in this run's synth directory — regenerate data "
                   "on the Generate tab.")
        nav_button("Go to step 1 — Generate data", PAGES[1], type="primary")
        return

    st.info("For the specification's validation profile (8 entities × 50 alerts, seed 7, "
            "anomaly rate 0.25) the expected result is two injected and detected cases per "
            "detector, and precision, recall, F1 = 1.000.")

    args = build_validate_args()
    show_cli(args)
    if st.button("Run validation", type="primary"):
        run_cli(args, title="satsa validate")

    met = compute_validation_metrics()
    if met:
        st.subheader("Recovery metrics")
        st.caption("Computed from flags.json and ground truth — the same key-set "
                   "comparison the CLI prints.")
        df = pd.DataFrame([{
            "detector": m["detector"], "injected": m["injected"], "detected": m["detected"],
            "true positives": m["tp"], "false positives": m["fp"],
            "false negatives": m["fn"],
            "precision": f"{m['precision']:.3f}", "recall": f"{m['recall']:.3f}",
            "f1": f"{m['f1']:.3f}"} for m in met])
        show_df(df)
        c = st.columns(3)
        for i, m in enumerate(met):
            c[i].metric(f"{m['short']} · F1", f"{m['f1']:.3f}",
                        f"P {m['precision']:.3f} · R {m['recall']:.3f}")
        if all(m["f1"] == 1.0 for m in met) and any(m["injected"] for m in met):
            st.success("Perfect recovery — every injected signal was detected with zero "
                       "false positives on this controlled dataset.")
    else:
        st.caption("Metrics could not be derived from this ground-truth schema — "
                   "see the raw CLI output above.")
    st.caption("Validation demonstrates recovery of injected conditions on controlled "
               "synthetic data; it does not by itself establish real-world supervisory "
               "effectiveness (see the real-world validation protocol).")
    nav_button("Back to overview", PAGES[0])

# --------------------------------------------------------------------------- #
# App chrome: setup banner, header, tab bar, footer, dispatch
# --------------------------------------------------------------------------- #
def render_setup_banner():
    st.error("The `satsa` CLI could not be located. This console drives the real "
             "SAT-SA tool, so install the package first:")
    st.code("pip install -e .", language="powershell")
    st.markdown("Or point the `SATSA_CMD` environment variable at the `satsa` executable "
                "(for example `C:\\repo\\.venv\\Scripts\\satsa.exe`) and reload this page.")


def render_chrome():
    """Consistent header on every page: hero, tab bar, run controls, pipeline strip."""
    st.markdown(HERO, unsafe_allow_html=True)
    if st.session_state.get("nav") not in PAGES:
        st.session_state.nav = PAGES[0]
    tabs_col, run_col = st.columns([3.6, 1.4], gap="medium")
    with tabs_col:
        st.radio("Section", PAGES, key="nav", horizontal=True,
                 label_visibility="collapsed")
    with run_col:
        st.text_input("Run label", key="run_name",
                      help="Artifacts are stored under runs/<label>/. Change the label "
                           "to start a fresh, isolated run.")
        st.button("New run", on_click=new_run_label,
                  help="Start a fresh run label named with the current timestamp.")
    render_pipeline_strip()
    st.caption(f'Run "{safe_run_label()}" — artifacts at `{run_root()}`')
    st.divider()


def footer():
    st.divider()
    cmd = satsa_command()
    backend = shlex.join(cmd) if cmd else "not found"
    st.caption(f"CLI backend: `{backend}` · SAT-SA v0.1.0 · Flags are prioritisation "
               f"signals for manual inspection, never proof of misconduct or an "
               f"automatic enforcement outcome. All analytics run locally; no telemetry "
               f"leaves the host.")
    if pq is None:
        st.caption("Note: pyarrow is unavailable — parquet statistics and previews are "
                   "limited.")


def main():
    if satsa_command() is None:
        render_setup_banner()
    render_chrome()
    dispatch = {
        PAGES[0]: page_overview,
        PAGES[1]: page_generate,
        PAGES[2]: page_ingest,
        PAGES[3]: page_detect,
        PAGES[4]: page_score,
        PAGES[5]: page_explain,
        PAGES[6]: page_validate,
    }
    dispatch.get(st.session_state.nav, page_overview)()
    footer()


main()