"""SAT-SA Streamlit demonstration workbench.

The CLI remains the analytics authority. This application makes the periodic
supervisory workflow demonstrable: create or provide a submission, validate it,
analyse it, then review evidence-led results.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
RUNS_ROOT = ROOT / "runs"
CONFIG_PATH = ROOT / "detector_config.yaml"
TABLES = ("entities", "assets", "alerts", "cases", "escalations")
PRESETS = {
    "Default — small demonstration": {"entities": 8, "alerts": 1_000, "rate": 0.25, "batch": 10_000, "description": "8,000 baseline alerts. Fast enough for a live classroom or judging demonstration."},
    "Medium — departmental assessment": {"entities": 20, "alerts": 10_000, "rate": 0.15, "batch": 25_000, "description": "200,000 baseline alerts. A realistic multi-entity periodic submission."},
    "Large — supervisory batch": {"entities": 40, "alerts": 50_000, "rate": 0.15, "batch": 50_000, "description": "2 million baseline alerts. Suitable for the primary scalability demonstration."},
    "Gigantic — national-scale rehearsal": {"entities": 100, "alerts": 100_000, "rate": 0.10, "batch": 100_000, "description": "10 million baseline alerts. Use only with sufficient disk, time, and memory headroom."},
}
SIGNALS = {"fast_closure": "Unusually fast closure", "no_escalation": "Critical alert without escalation", "low_coverage": "Low critical-asset coverage"}


def safe_name(value: str) -> str:
    return (re.sub(r"[^A-Za-z0-9_-]+", "-", value.strip()).strip("-_") or "supervisory-run")[:64]


def paths_for_current_run() -> dict[str, Path]:
    root = RUNS_ROOT / safe_name(st.session_state.get("run_name", "sih-demo"))
    return {"root": root, "source": root / "source", "normalized": root / "normalized", "results": root / "results"}


def run_cli(args: list[str], label: str) -> tuple[int, str]:
    """Show local CLI progress without duplicating CLI functionality in the UI."""
    started = time.perf_counter()
    lines: list[str] = []
    with st.status(label, expanded=True) as status:
        viewport = st.empty()
        process = subprocess.Popen([sys.executable, "-m", "sat_sa.cli", *args], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line.rstrip())
            viewport.code("\n".join(lines[-25:]) or "Preparing local run…", language="text")
        returncode = process.wait()
        elapsed = time.perf_counter() - started
        status.update(label=f"{label}: {'completed' if returncode == 0 else 'failed'} in {elapsed:.1f}s", state="complete" if returncode == 0 else "error")
    return returncode, "\n".join(lines)


def run_full_assessment(paths: dict[str, Path], generate_args: list[str] | None = None, adaptive: bool = True) -> bool:
    """Run the entire CLI sequence after the user presses one start button."""
    paths["root"].mkdir(parents=True, exist_ok=True)
    stages: list[tuple[str, list[str]]] = []
    if generate_args is not None:
        stages.append(("1 of 5 — Creating SOC submission", generate_args))
    offset = 1 if generate_args is not None else 0
    ingest_args = ["ingest", "--input", str(paths["source"]), "--format", "csv", "--batch-size", "0", "--workers", "0", "--out", str(paths["normalized"])]
    detect_args = ["detect", "--data", str(paths["normalized"]), "--detectors", "execution_gaps,negative_space", "--config", str(CONFIG_PATH), "--batch-size", "0", "--workers", "0", "--out", str(paths["results"] / "flags.json")]
    if not adaptive:
        ingest_args.append("--no-adaptive")
        detect_args.append("--no-adaptive")
    stages.extend([
        (f"{offset + 1} of {offset + 4} — Validating submitted records", ingest_args),
        (f"{offset + 2} of {offset + 4} — Detecting supervisory signals", detect_args),
        (f"{offset + 3} of {offset + 4} — Ranking CSEs for review", ["score", "--flags", str(paths["results"] / "flags.json"), "--config", str(CONFIG_PATH), "--out", str(paths["results"] / "entity_scores.csv")]),
        (f"{offset + 4} of {offset + 4} — Publishing evidence report", ["report", "--scores", str(paths["results"] / "entity_scores.csv"), "--flags", str(paths["results"] / "flags.json"), "--format", "json", "--out", str(paths["results"] / "report.json")]),
    ])
    progress = st.progress(0, text="Preparing assessment workflow")
    for number, (label, arguments) in enumerate(stages, start=1):
        returncode, _ = run_cli(arguments, label)
        if returncode != 0:
            progress.empty()
            st.error("The assessment stopped. Correct the reported issue and start this run again.")
            return False
        progress.progress(number / len(stages), text=label)
    progress.empty()
    read_flags.clear(); read_scores.clear()
    return True


@st.cache_data(show_spinner=False)
def read_flags(path_text: str, modified_at: float) -> pd.DataFrame:
    path = Path(path_text)
    if not path.exists():
        return pd.DataFrame()
    payload = json.loads(path.read_text(encoding="utf-8"))
    source = payload.get("flags", []) if isinstance(payload, dict) else payload
    rows: list[dict[str, Any]] = []
    for flag in source:
        evidence = flag.get("evidence", {})
        identifiers = evidence.get("alert_ids", []) or evidence.get("asset_ids", [])
        rows.append({"Finding": flag.get("flag_id"), "CSE": flag.get("entity_id"), "Signal": SIGNALS.get(flag.get("detector"), flag.get("detector")), "Record": ", ".join(map(str, identifiers)), "Rationale": flag.get("rationale", ""), "Evidence": evidence})
    return pd.DataFrame(rows)


@st.cache_data(show_spinner=False)
def read_scores(path_text: str, modified_at: float) -> pd.DataFrame:
    path = Path(path_text)
    if not path.exists():
        return pd.DataFrame()
    result = pd.read_csv(path)
    for column in ("risk_score", "priority_rank", "distinct_detectors_triggered", "alert_volume"):
        if column in result:
            result[column] = pd.to_numeric(result[column], errors="coerce")
    return result


def artifacts() -> tuple[pd.DataFrame, pd.DataFrame]:
    paths = paths_for_current_run()
    flags_file, scores_file = paths["results"] / "flags.json", paths["results"] / "entity_scores.csv"
    flags = read_flags(str(flags_file), flags_file.stat().st_mtime if flags_file.exists() else 0.0)
    scores = read_scores(str(scores_file), scores_file.stat().st_mtime if scores_file.exists() else 0.0)
    return flags, scores


def workflow(paths: dict[str, Path]) -> list[tuple[str, bool, str]]:
    source = all((paths["source"] / f"{table}.csv").exists() for table in TABLES)
    normalized = all((paths["normalized"] / f"{table}.parquet").exists() for table in TABLES)
    detected = (paths["results"] / "flags.json").exists()
    scored = detected and (paths["results"] / "entity_scores.csv").exists()
    return [("Submission", source, "Synthetic data or five uploaded CSV exports"), ("Validation", normalized, "Schema-checked parquet tables and rejects audit"), ("Analytics", detected, "Execution gaps and negative space detected"), ("Prioritisation", scored, "Ranked CSE queue and report available")]


def sidebar() -> None:
    with st.sidebar:
        st.header("SAT-SA")
        st.caption("Supervisory analytics demonstration")
        st.text_input("Demonstration run name", key="run_name", help="Files are kept in runs/<name> so demonstrations remain separate.")
        paths = paths_for_current_run()
        st.caption(f"Workspace: {paths['root'].relative_to(ROOT)}")


def workflow_page() -> None:
    st.title("Run a supervisory assessment")
    st.write("Choose one of two routes. Once you press Start, SAT-SA completes validation, analytics, prioritisation, and report generation automatically using the existing offline CLI.")
    route = st.segmented_control("Assessment route", ["Synthetic demonstration", "Upload CSE CSV files"], default="Synthetic demonstration")
    paths = paths_for_current_run()
    if route == "Synthetic demonstration":
        selected = st.radio("Dataset scale", list(PRESETS), index=0)
        preset = PRESETS[selected]
        a, b, c, d = st.columns(4)
        a.metric("CSEs", f"{preset['entities']:,}")
        b.metric("Alerts per CSE", f"{preset['alerts']:,}")
        c.metric("Baseline alerts", f"{preset['entities'] * preset['alerts']:,}")
        d.metric("Injected entities", f"{preset['rate']:.0%}")
        st.info(preset["description"])
        with st.expander("Adjust selected preset"):
            entities = st.number_input("CSE count", min_value=4, value=preset["entities"], step=1)
            alerts = st.number_input("Alerts per CSE", min_value=1, value=preset["alerts"], step=max(1, preset["alerts"] // 10))
            rate = st.slider("Injected anomaly rate", 0.01, 1.0, float(preset["rate"]), 0.01)
            seed = st.number_input("Reproducibility seed", min_value=0, value=42, step=1)
            adaptive = st.toggle("Adaptive resource control", value=True)
        if st.button("Start synthetic assessment", type="primary"):
            paths["source"].parent.mkdir(parents=True, exist_ok=True)
            generation = ["generate-synth", "--entities", str(entities), "--alerts-per-entity", str(alerts), "--seed", str(seed), "--anomaly-rate", str(rate), "--batch-size", str(preset["batch"]), "--out", str(paths["source"])]
            if not adaptive:
                generation.append("--no-adaptive")
            if run_full_assessment(paths, generation, adaptive):
                st.success("Assessment complete. Open Review results to present the prioritised evidence.")
    else:
        st.caption("Required: entities.csv, assets.csv, alerts.csv, cases.csv, escalations.csv. Cases and escalations may contain headers only.")
        uploads = st.file_uploader("Select CSV exports", type=["csv"], accept_multiple_files=True)
        adaptive_upload = st.toggle("Adaptive resource control", value=True, key="upload_adaptive")
        names = {Path(upload.name).stem for upload in uploads} if uploads else set()
        missing = set(TABLES) - names
        if uploads and missing:
            st.warning(f"Missing required tables: {', '.join(sorted(missing))}")
        if uploads and not missing:
            st.success("All required tables are present. Start will store and process them automatically.")
        if st.button("Start assessment from uploaded files", type="primary", disabled=not uploads or bool(missing)):
            paths["source"].mkdir(parents=True, exist_ok=True)
            for upload in uploads:
                if Path(upload.name).stem in TABLES:
                    (paths["source"] / Path(upload.name).name).write_bytes(upload.getbuffer())
            if run_full_assessment(paths, adaptive=adaptive_upload):
                st.success("Assessment complete. Open Review results to inspect ranked CSEs and evidence.")


def review_page() -> None:
    st.title("Review supervisory results")
    flags, scores = artifacts()
    paths = paths_for_current_run()
    if flags.empty or scores.empty:
        st.info("No completed result set is available for this run. Complete the earlier workflow steps first.")
        return

    ranked = scores.sort_values("priority_rank")
    counts = Counter(flags["Signal"])

    a, b, c, d = st.columns(4)
    a.metric("Entities analysed", f"{len(scores):,}")
    b.metric("Findings for review", f"{len(flags):,}")
    c.metric(
        "Highest priority",
        str(ranked.iloc[0]["entity_id"]),
        f"Risk score {ranked.iloc[0]['risk_score']:.4f}",
    )
    d.metric("Signal types", f"{len(counts)}/3")

    queue, evidence, validation = st.tabs(
        ["Priority queue", "Evidence drill-down", "Synthetic validation"]
    )

    with queue:
        st.subheader("Entities to review first")

        table = ranked[
            [
                "priority_rank",
                "entity_id",
                "risk_score",
                "distinct_detectors_triggered",
                "alert_volume",
            ]
        ].copy()
        table.columns = [
            "Rank",
            "CSE",
            "Risk score",
            "Distinct signals",
            "Alert volume",
        ]

        st.dataframe(
            table,
            hide_index=True,
            width="stretch",
            column_config={
                "Risk score": st.column_config.NumberColumn(format="%.4f"),
                "Alert volume": st.column_config.NumberColumn(format="%d"),
            },
        )

        risk_chart, signal_chart = st.columns(2)

        with risk_chart:
            st.caption("Priority score by CSE")
            st.bar_chart(
                ranked.head(15).set_index("entity_id")[["risk_score"]],
                horizontal=True,
            )

        with signal_chart:
            st.caption("Findings by supervisory signal")
            st.bar_chart(
                pd.DataFrame({"Findings": counts}).rename_axis("Signal"),
                horizontal=True,
            )

        st.caption(
            "Priority directs human review effort; it is not an automated supervisory conclusion."
        )

    with evidence:
        entities = st.multiselect(
            "CSE filter",
            sorted(flags["CSE"].unique()),
            placeholder="All CSEs",
        )
        signals = st.multiselect(
            "Signal filter",
            sorted(flags["Signal"].unique()),
            default=sorted(flags["Signal"].unique()),
        )

        visible = flags.copy()

        if entities:
            visible = visible[visible["CSE"].isin(entities)]

        if signals:
            visible = visible[visible["Signal"].isin(signals)]

        st.caption(f"{len(visible):,} findings ready for examination.")

        for _, finding in visible.iterrows():
            with st.expander(
                f"{finding['Finding']} | {finding['CSE']} | {finding['Signal']}"
            ):
                st.write(finding["Rationale"])

                st.subheader("Underlying record")
                source_rows = finding["Evidence"].get("source_rows", [])

                if source_rows:
                    st.dataframe(
                        pd.DataFrame(source_rows),
                        hide_index=True,
                        width="stretch",
                    )
                else:
                    st.caption("No source row attached.")

                st.subheader("Evidence summary")
                st.json(
                    {
                        key: value
                        for key, value in finding["Evidence"].items()
                        if key != "source_rows"
                    }
                )

        if not visible.empty:
            st.subheader("Entity signal profile")
            chosen = st.selectbox(
                "CSE evidence profile",
                sorted(visible["CSE"].unique()),
            )
            profile = (
                visible[visible["CSE"] == chosen]
                .groupby("Signal")
                .size()
                .rename("Findings")
                .to_frame()
            )
            st.bar_chart(profile, horizontal=True)

    with validation:
        truth = paths["source"] / "ground_truth.parquet"

        if truth.exists():
            if st.button("Validate against synthetic ground truth"):
                run_cli(
                    [
                        "validate",
                        "--flags",
                        str(paths["results"] / "flags.json"),
                        "--synth-ground-truth",
                        str(truth),
                    ],
                    "Validating synthetic findings",
                )
        else:
            st.info(
                "Synthetic ground truth exists only for generated demonstrations. "
                "Real CSE submissions are compared with independent examiner findings."
            )

def method_page() -> None:
    st.title("How SAT-SA works")
    st.write("SAT-SA is a periodic supervisory capability, not a SIEM or real-time SOC. It turns structured operating evidence into a traceable review queue.")
    steps = [("Periodic submission", "CSEs provide alerts, assets, case-management, and escalation exports."), ("Validation and audit", "Every record is checked; malformed data is recorded in rejects.json."), ("Supervisory analytics", "Explainable rules identify fast closure, missing escalation, and possible monitoring blind spots."), ("Peer comparison", "Activity is compared with severity baselines or peer cohorts."), ("Human review", "Examiners inspect the records and decide the supervisory outcome.")]
    for number, (heading, body) in enumerate(steps, 1):
        with st.container(border=True):
            st.subheader(f"{number}. {heading}")
            st.write(body)
    st.subheader("Deployment characteristics")
    st.markdown("- Local Python and parquet processing\n- No cloud, hosted model, or runtime Internet dependency\n- Bounded batches with optional adaptive resource scaling\n- JSON evidence records for audit and reporting")


def setup() -> None:
    st.set_page_config(page_title="SAT-SA | Supervisory Analytics", page_icon="", layout="wide", initial_sidebar_state="expanded")


def main() -> None:
    setup()
    if "run_name" not in st.session_state:
        st.session_state.run_name = "sih-demo"
    navigation = st.navigation({"Assessment": [st.Page(workflow_page, title="Run assessment", icon=":material/play_circle:"), st.Page(review_page, title="Review results", icon=":material/fact_check:")], "Reference": [st.Page(method_page, title="How it works", icon=":material/account_tree:")]})
    sidebar()
    navigation.run()


if __name__ == "__main__":
    main()
