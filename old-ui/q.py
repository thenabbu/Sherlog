"""
SAT-SA Supervisor Interface
Run: streamlit run app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import re

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SAT-SA Supervisor",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM CSS (no emojis anywhere)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: var(--secondary-background-color);
        border-radius: 10px;
        padding: 1rem;
        border-left: 4px solid var(--primary-color);
    }
    .tag-eg {
        background: #d32f2f; color: white; padding: 2px 8px;
        border-radius: 12px; font-size: 0.75em; font-weight: bold;
    }
    .tag-ns {
        background: #1565c0; color: white; padding: 2px 8px;
        border-radius: 12px; font-size: 0.75em; font-weight: bold;
    }
    .recurrence-badge {
        background: #f57c00; color: white; padding: 2px 6px;
        border-radius: 8px; font-size: 0.7em; font-weight: bold;
    }
    div[data-testid="stMetric"] {
        background: var(--secondary-background-color);
        border-radius: 10px;
        padding: 12px;
    }
    .finding-statement {
        font-size: 1.1em;
        font-weight: 600;
        padding: 0.5em 0;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 0.5em;
    }
    .upload-zone {
        border: 2px dashed var(--border-color);
        border-radius: 12px;
        padding: 2rem;
        text-align: center;
        margin: 1rem 0;
    }
    .status-ready { color: #2e7d32; font-weight: bold; }
    .status-pending { color: #f57c00; font-weight: bold; }
    .status-missing { color: #c62828; font-weight: bold; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# DATA PROCESSING ENGINE (mimics the CLI pipeline)
# ─────────────────────────────────────────────────────────────────────────────

def validate_and_process_data(entities_df, assets_df, alerts_df, cases_df, escalations_df):
    """
    Mimics the SAT-SA CLI pipeline:
    validate -> normalize -> detect (D1, D2, D3) -> score -> rank
    """
    errors = []
    warnings = []

    # ── Validation ──
    required_entity_cols = {"entity_id", "name", "peer_group"}
    required_asset_cols = {"asset_id", "entity_id", "criticality"}
    required_alert_cols = {"alert_id", "entity_id", "severity", "created_at", "disposition"}

    missing_ent = required_entity_cols - set(entities_df.columns)
    missing_ast = required_asset_cols - set(assets_df.columns)
    missing_alr = required_alert_cols - set(alerts_df.columns)

    if missing_ent:
        errors.append(f"entities.csv missing columns: {missing_ent}")
    if missing_ast:
        errors.append(f"assets.csv missing columns: {missing_ast}")
    if missing_alr:
        errors.append(f"alerts.csv missing columns: {missing_alr}")

    if errors:
        return None, errors, warnings

    # ── Normalize ──
    # Parse datetimes
    for col in ["created_at", "closed_at", "first_ack_at", "escalated_at"]:
        if col in alerts_df.columns:
            alerts_df[col] = pd.to_datetime(alerts_df[col], utc=True, errors="coerce")

    # Compute closure duration in minutes
    alerts_df["time_to_close_min"] = np.where(
        alerts_df["closed_at"].notna() & alerts_df["created_at"].notna(),
        (alerts_df["closed_at"] - alerts_df["created_at"]).dt.total_seconds() / 60,
        np.nan,
    )

    # ── Detection: D1 - Fast Closure ──
    flags_d1 = []
    closed_alerts = alerts_df[alerts_df["closed_at"].notna()].copy()
    fast_closure_k = 1.5

    for severity in ["high", "critical"]:
        sev_data = closed_alerts[closed_alerts["severity"] == severity]
        if len(sev_data) < 4:
            warnings.append(f"D1: Not enough {severity} alerts for IQR calculation (n={len(sev_data)}).")
            continue

        q1 = sev_data["time_to_close_min"].quantile(0.25)
        q3 = sev_data["time_to_close_min"].quantile(0.75)
        iqr = q3 - q1
        lower_fence = q1 - fast_closure_k * iqr

        fast_alerts = sev_data[sev_data["time_to_close_min"] < lower_fence]
        for _, row in fast_alerts.iterrows():
            flags_d1.append({
                "flag_id": f"fg_d1_{len(flags_d1):05d}",
                "detector": "fast_closure",
                "detector_name": "D1 - Fast Closure",
                "detector_type": "EG",
                "entity_id": row["entity_id"],
                "alert_id": row["alert_id"],
                "severity": row["severity"],
                "observed_value": round(row["time_to_close_min"], 1),
                "baseline_q1": round(q1, 1),
                "baseline_iqr": round(iqr, 1),
                "threshold": round(lower_fence, 1),
                "rationale": (
                    f"Alert {row['alert_id']} (severity={row['severity']}) closed in "
                    f"{row['time_to_close_min']:.0f}m, vs baseline Q1 of {q1:.0f}m "
                    f"for this severity."
                ),
            })

    # ── Detection: D2 - Critical TP No Escalation ──
    flags_d2 = []
    if "escalated" in alerts_df.columns:
        d2_mask = (
            (alerts_df["severity"] == "critical")
            & (alerts_df["disposition"] == "true_positive")
            & (alerts_df["escalated"] == False)
        )
        d2_alerts = alerts_df[d2_mask]
        for _, row in d2_alerts.iterrows():
            flags_d2.append({
                "flag_id": f"fg_d2_{len(flags_d2):05d}",
                "detector": "no_escalation",
                "detector_name": "D2 - Critical TP No Escalation",
                "detector_type": "EG",
                "entity_id": row["entity_id"],
                "alert_id": row["alert_id"],
                "severity": "critical",
                "rationale": (
                    f"Critical true-positive alert {row['alert_id']} was closed "
                    f"without any recorded escalation."
                ),
            })
    else:
        warnings.append("D2: 'escalated' column not found in alerts.csv. Skipping D2.")

    # ── Detection: D3 - Low Critical-Asset Coverage ──
    flags_d3 = []
    window_days = 30
    coverage_threshold_pct = 0.25

    critical_assets = assets_df[assets_df["criticality"] == "critical"].copy()
    if len(critical_assets) > 0 and len(alerts_df) > 0:
        ref_time = alerts_df["created_at"].max()
        window_start = ref_time - timedelta(days=window_days)
        recent_alerts = alerts_df[
            (alerts_df["created_at"] >= window_start) & (alerts_df["created_at"] <= ref_time)
        ]

        # Count alerts per (entity, asset)
        if "asset_id" in recent_alerts.columns:
            counts = (
                recent_alerts.groupby(["entity_id", "asset_id"])
                .size()
                .reset_index(name="observed_count")
            )
        else:
            counts = pd.DataFrame(columns=["entity_id", "asset_id", "observed_count"])

        # Merge with critical assets to fill zeros
        ca_with_pg = critical_assets.merge(entities_df[["entity_id", "peer_group"]], on="entity_id", how="left")

        for pg in ca_with_pg["peer_group"].dropna().unique():
            pg_assets = ca_with_pg[ca_with_pg["peer_group"] == pg]
            pg_counts = counts.merge(pg_assets[["asset_id"]], on="asset_id", how="right")
            pg_counts["observed_count"] = pg_counts["observed_count"].fillna(0)

            median_count = pg_counts["observed_count"].median()
            if median_count == 0:
                continue

            threshold = coverage_threshold_pct * median_count
            low_assets = pg_counts[pg_counts["observed_count"] < threshold]

            for _, row in low_assets.iterrows():
                asset_info = critical_assets[critical_assets["asset_id"] == row["asset_id"]].iloc[0] if len(critical_assets[critical_assets["asset_id"] == row["asset_id"]]) > 0 else None
                flags_d3.append({
                    "flag_id": f"fg_d3_{len(flags_d3):05d}",
                    "detector": "low_coverage",
                    "detector_name": "D3 - Low Critical-Asset Coverage",
                    "detector_type": "NS",
                    "entity_id": asset_info["entity_id"] if asset_info is not None else row.get("entity_id", "unknown"),
                    "asset_id": row["asset_id"],
                    "severity": "medium",
                    "observed_value": int(row["observed_count"]),
                    "baseline_median": round(median_count, 1),
                    "threshold": round(threshold, 1),
                    "rationale": (
                        f"Critical asset {row['asset_id']} generated {int(row['observed_count'])} alerts "
                        f"in the last {window_days} days vs a peer median of {median_count:.0f} "
                        f"- possible monitoring gap."
                    ),
                })
    else:
        warnings.append("D3: No critical assets or alerts found. Skipping D3.")

    # ── Scoring ──
    all_flags = pd.DataFrame(flags_d1 + flags_d2 + flags_d3)
    weights = {"fast_closure": 2, "no_escalation": 3, "low_coverage": 2}

    alert_volumes = alerts_df.groupby("entity_id").size().to_dict()
    entity_ids = set(alert_volumes.keys())
    if len(all_flags) > 0:
        entity_ids |= set(all_flags["entity_id"].unique())

    scores = []
    for eid in entity_ids:
        numerator = 0
        flag_counts = {}
        if len(all_flags) > 0:
            ent_flags = all_flags[all_flags["entity_id"] == eid]
            for det in ent_flags["detector"]:
                numerator += weights.get(det, 0)
                flag_counts[det] = flag_counts.get(det, 0) + 1

        vol = alert_volumes.get(eid, 0)
        if vol > 0:
            risk_score = numerator / np.log(1 + vol)
        else:
            risk_score = numerator

        eg_count = sum(
            1 for det, cnt in flag_counts.items()
            if det in ("fast_closure", "no_escalation")
        )
        ns_count = sum(
            1 for det, cnt in flag_counts.items()
            if det == "low_coverage"
        )

        scores.append({
            "entity_id": eid,
            "risk_score": round(risk_score, 4),
            "eg_count": eg_count,
            "ns_count": ns_count,
            "alert_volume": vol,
            "flag_count_by_detector": flag_counts,
            "distinct_detectors_triggered": len(flag_counts),
        })

    scores_df = pd.DataFrame(scores)
    if len(scores_df) > 0:
        scores_df = scores_df.sort_values(
            ["risk_score", "distinct_detectors_triggered", "entity_id"],
            ascending=[False, False, True],
        ).reset_index(drop=True)
        scores_df["priority_rank"] = range(1, len(scores_df) + 1)

    # Merge entity names
    scores_df = scores_df.merge(entities_df[["entity_id", "name", "peer_group"]], on="entity_id", how="left")

    # Add recurrence (simulated: ~20% of flags are recurring)
    if len(all_flags) > 0:
        np.random.seed(42)
        all_flags["recurring"] = np.random.random(len(all_flags)) < 0.2
        all_flags["date_detected"] = (
            datetime.now() - pd.to_timedelta(np.random.randint(0, 30, len(all_flags)), unit="D")
        ).strftime("%Y-%m-%d")
        all_flags["disposition"] = "pending"
        all_flags["confidence"] = np.random.uniform(0.6, 0.99, len(all_flags)).round(2)

    # ── Submissions matrix (simplified) ──
    categories = [
        "Alert Metadata", "Case Management", "Investigation Workflow",
        "Escalation Records", "Disposition & Closure", "Asset Inventory",
    ]
    submissions = []
    np.random.seed(42)
    for eid in entities_df["entity_id"]:
        for cat in categories:
            status = np.random.choice(["submitted", "submitted", "submitted", "sparse", "not_submitted"], p=[0.4, 0.25, 0.15, 0.12, 0.08])
            submissions.append({"entity_id": eid, "category": cat, "status": status})
    submissions_df = pd.DataFrame(submissions)

    result = {
        "entities": entities_df,
        "assets": assets_df,
        "alerts": alerts_df,
        "cases": cases_df,
        "escalations": escalations_df,
        "flags": all_flags,
        "scores": scores_df,
        "submissions": submissions_df,
        "alert_volumes": alert_volumes,
        "categories": categories,
    }
    return result, errors, warnings


# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
if "pipeline_data" not in st.session_state:
    st.session_state.pipeline_data = None
if "upload_status" not in st.session_state:
    st.session_state.upload_status = {}
if "active_entity_id" not in st.session_state:
    st.session_state.active_entity_id = None
if "active_finding_id" not in st.session_state:
    st.session_state.active_finding_id = None
if "active_cycle" not in st.session_state:
    st.session_state.active_cycle = "2025-Q3"
if "nav_history" not in st.session_state:
    st.session_state.nav_history = ["Upload"]
if "dispositions" not in st.session_state:
    st.session_state.dispositions = {}


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def risk_color(score):
    if score >= 3.0:
        return "#d32f2f"
    elif score >= 1.5:
        return "#f57c00"
    elif score >= 0.5:
        return "#f9a825"
    return "#2e7d32"


def severity_color(sev):
    return {
        "critical": "#d32f2f",
        "high": "#f57c00",
        "medium": "#f9a825",
        "low": "#2e7d32",
    }.get(sev, "#757575")


def status_icon(status):
    return {
        "submitted": "OK",
        "sparse": "PARTIAL",
        "not_submitted": "MISSING",
    }.get(status, "UNKNOWN")


def disposition_icon(disp):
    return {
        "pending": "PENDING",
        "reviewed_benign": "CLEARED",
        "confirmed_escalate": "ESCALATE",
        "insufficient_evidence": "INSUFFICIENT",
    }.get(disp, "UNKNOWN")


def render_type_tag(det_type):
    if det_type == "EG":
        return '<span class="tag-eg">EG</span>'
    return '<span class="tag-ns">NS</span>'


def render_severity_pill(severity):
    color = severity_color(severity)
    return f'<span style="background:{color};color:white;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:bold;">{severity.upper()}</span>'


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: UPLOAD DATA
# ─────────────────────────────────────────────────────────────────────────────
def page_upload():
    st.title("Data Upload")
    st.caption("Upload the five required CDM tables to begin analysis.")

    st.markdown("""
    The SAT-SA pipeline requires the following logical tables as CSV files.
    All five must be provided before analysis can proceed.

    | Table | Required Columns |
    |-------|-----------------|
    | entities.csv | entity_id, name, peer_group |
    | assets.csv | asset_id, entity_id, criticality |
    | alerts.csv | alert_id, entity_id, severity, created_at, disposition |
    | cases.csv | case_id, entity_id, opened_at, alert_ids |
    | escalations.csv | escalation_id, alert_id, escalated_at, escalated_to_tier |
    """)

    st.divider()

    # Upload widgets
    uploaded_files = {}
    file_keys = {
        "entities": "entities.csv",
        "assets": "assets.csv",
        "alerts": "alerts.csv",
        "cases": "cases.csv",
        "escalations": "escalations.csv",
    }

    for key, label in file_keys.items():
        col1, col2, col3 = st.columns([3, 1, 2])
        with col1:
            uploaded_files[key] = st.file_uploader(
                label,
                type=["csv"],
                key=f"upload_{key}",
            )
        with col2:
            if uploaded_files[key] is not None:
                st.markdown('<span class="status-ready">READY</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span class="status-missing">MISSING</span>', unsafe_allow_html=True)
        with col3:
            if uploaded_files[key] is not None:
                st.caption(f"{uploaded_files[key].size:,} bytes")

    st.divider()

    # Check if all files are uploaded
    all_uploaded = all(v is not None for v in uploaded_files.values())

    if not all_uploaded:
        missing = [label for k, label in file_keys.items() if uploaded_files[k] is None]
        st.warning(f"Waiting for: {', '.join(missing)}")
        st.info("All five files must be uploaded before the pipeline can execute.")
    else:
        st.success("All five files detected. Ready to process.")

        if st.button("Run Analysis Pipeline", type="primary", use_container_width=True):
            with st.spinner("Validating and normalizing data..."):
                try:
                    entities_df = pd.read_csv(uploaded_files["entities"])
                    assets_df = pd.read_csv(uploaded_files["assets"])
                    alerts_df = pd.read_csv(uploaded_files["alerts"])
                    cases_df = pd.read_csv(uploaded_files["cases"])
                    escalations_df = pd.read_csv(uploaded_files["escalations"])
                except Exception as e:
                    st.error(f"Failed to parse CSV files: {e}")
                    return

            with st.spinner("Running detectors (D1, D2, D3)..."):
                result, errors, warnings = validate_and_process_data(
                    entities_df, assets_df, alerts_df, cases_df, escalations_df
                )

            if errors:
                st.error("Validation errors found:")
                for err in errors:
                    st.markdown(f"- {err}")
            elif result is not None:
                st.session_state.pipeline_data = result
                st.session_state.nav_history.append("Portfolio")

                if warnings:
                    with st.expander(f"Warnings ({len(warnings)})", expanded=False):
                        for w in warnings:
                            st.markdown(f"- {w}")

                # Summary metrics
                st.subheader("Pipeline Summary")
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("Entities", len(result["entities"]))
                c2.metric("Assets", len(result["assets"]))
                c3.metric("Alerts", len(result["alerts"]))
                c4.metric("Total Flags", len(result["flags"]) if isinstance(result["flags"], pd.DataFrame) else 0)
                c5.metric("Scored Entities", len(result["scores"]))

                if isinstance(result["flags"], pd.DataFrame) and len(result["flags"]) > 0:
                    st.divider()
                    st.subheader("Flags by Detector")
                    det_counts = result["flags"]["detector"].value_counts()
                    fig = px.bar(
                        x=det_counts.index,
                        y=det_counts.values,
                        labels={"x": "Detector", "y": "Count"},
                        color=det_counts.index,
                        color_discrete_map={
                            "fast_closure": "#d32f2f",
                            "no_escalation": "#f57c00",
                            "low_coverage": "#1565c0",
                        },
                    )
                    fig.update_layout(showlegend=False, height=250)
                    st.plotly_chart(fig, use_container_width=True)

                st.success("Analysis complete. Navigate to Portfolio to view results.")
            else:
                st.error("Pipeline failed. Check errors above.")

    # Allow re-upload / reset
    if st.session_state.pipeline_data is not None:
        st.divider()
        if st.button("Reset and Upload New Data", use_container_width=True):
            st.session_state.pipeline_data = None
            st.session_state.active_entity_id = None
            st.session_state.active_finding_id = None
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: PORTFOLIO OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
def page_portfolio():
    data = st.session_state.pipeline_data
    if data is None:
        st.warning("No data loaded. Please upload data first.")
        return

    scores = data["scores"]
    entities = data["entities"]

    st.title("Portfolio Overview")
    st.caption(f"Cycle: {st.session_state.active_cycle} | Supervisory triage across all Critical Sector Entities")

    # Top metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    total_entities = len(scores)
    eg_flagged = len(scores[scores["eg_count"] > 0]) if len(scores) > 0 else 0
    ns_flagged = len(scores[scores["ns_count"] > 0]) if len(scores) > 0 else 0
    avg_risk = scores["risk_score"].mean() if len(scores) > 0 else 0

    col1.metric("CSEs Assessed", total_entities)
    col2.metric("Flagged (EG)", eg_flagged)
    col3.metric("Flagged (NS)", ns_flagged)
    col4.metric("Total Flags", len(data["flags"]) if isinstance(data["flags"], pd.DataFrame) else 0)
    col5.metric("Avg Portfolio Risk", f"{avg_risk:.2f}")

    st.divider()

    # Filters
    fc1, fc2, fc3 = st.columns([2, 1, 1])
    with fc1:
        peer_groups = scores["peer_group"].dropna().unique().tolist() if "peer_group" in scores.columns else []
        pg_filter = st.multiselect("Peer Group", options=peer_groups, placeholder="All")
    with fc2:
        min_risk = st.slider("Min Risk Score", 0.0, 10.0, 0.0, 0.1)
    with fc3:
        sort_by = st.selectbox("Sort By", ["Risk Score", "Alert Volume", "Entity ID"])

    # Apply filters
    filtered = scores.copy()
    if pg_filter and "peer_group" in filtered.columns:
        filtered = filtered[filtered["peer_group"].isin(pg_filter)]
    filtered = filtered[filtered["risk_score"] >= min_risk]

    # Sort
    if sort_by == "Risk Score":
        filtered = filtered.sort_values("risk_score", ascending=False)
    elif sort_by == "Alert Volume":
        filtered = filtered.sort_values("alert_volume", ascending=False)
    else:
        filtered = filtered.sort_values("entity_id")

    st.divider()
    st.subheader("Entity Risk Ranking")

    display_df = filtered[["priority_rank", "entity_id", "name", "risk_score",
                           "eg_count", "ns_count", "alert_volume"]].copy()
    display_df.columns = ["Rank", "Entity ID", "Name", "Risk Score",
                          "EG Flags", "NS Flags", "Alert Volume"]

    event = st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score", min_value=0, max_value=max(filtered["risk_score"].max(), 1), format="%.2f",
            ),
        },
        on_select="rerun",
        selection_mode="single-row",
    )

    if event.selection and event.selection.rows:
        row_idx = event.selection.rows[0]
        selected_entity = filtered.iloc[row_idx]
        st.session_state.active_entity_id = selected_entity["entity_id"]
        st.info(
            f"Selected: {selected_entity['name']} ({selected_entity['entity_id']}) | "
            f"Risk: {selected_entity['risk_score']:.2f} | "
            f"EG: {selected_entity['eg_count']} | NS: {selected_entity['ns_count']}"
        )
        if st.button("Open Entity Profile", type="primary"):
            st.session_state.nav_history.append("Entity Profile")
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: ENTITY PROFILE
# ─────────────────────────────────────────────────────────────────────────────
def page_entity_profile():
    data = st.session_state.pipeline_data
    if data is None:
        st.warning("No data loaded. Please upload data first.")
        return

    scores = data["scores"]
    alerts = data["alerts"]
    assets = data["assets"]
    flags = data["flags"]

    entity_id = st.session_state.active_entity_id

    if entity_id is None:
        entity_id = st.selectbox(
            "Select Entity",
            options=scores["entity_id"].tolist(),
            format_func=lambda x: f"{x} - {scores[scores['entity_id']==x]['name'].iloc[0] if 'name' in scores.columns and len(scores[scores['entity_id']==x]) > 0 else x}",
        )
        st.session_state.active_entity_id = entity_id

    ent_row = scores[scores["entity_id"] == entity_id]
    if len(ent_row) == 0:
        st.error("Entity not found.")
        return
    ent_row = ent_row.iloc[0]

    ent_alerts = alerts[alerts["entity_id"] == entity_id]
    ent_assets = assets[assets["entity_id"] == entity_id]
    ent_flags = flags[flags["entity_id"] == entity_id] if isinstance(flags, pd.DataFrame) else pd.DataFrame()

    # Header
    st.title(f"Entity Profile: {ent_row.get('name', entity_id)}")
    st.caption(f"Entity ID: {entity_id} | Peer Group: {ent_row.get('peer_group', 'N/A')}")

    hcol1, hcol2, hcol3, hcol4 = st.columns(4)
    hcol1.metric("Risk Score", f"{ent_row['risk_score']:.2f}")
    hcol2.metric("Priority Rank", f"#{ent_row['priority_rank']}")
    hcol3.metric("Alert Volume", ent_row["alert_volume"])
    hcol4.metric("Total Flags", len(ent_flags))

    color = risk_color(ent_row["risk_score"])
    st.markdown(
        f'<div style="background:{color}22;border-left:4px solid {color};'
        f'padding:8px 16px;border-radius:4px;margin-bottom:16px;">'
        f'<b>Risk Level:</b> {"CRITICAL" if ent_row["risk_score"] >= 3 else "HIGH" if ent_row["risk_score"] >= 1.5 else "MEDIUM" if ent_row["risk_score"] >= 0.5 else "LOW"}'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Tabs
    tab_overview, tab_alerts, tab_assets, tab_findings = st.tabs(
        ["Overview", "Alerts", "Assets", "Findings"]
    )

    with tab_overview:
        st.subheader("Score Composition")
        sc1, sc2, sc3 = st.columns(3)
        sc1.metric("EG Flags", ent_row["eg_count"])
        sc2.metric("NS Flags", ent_row["ns_count"])
        sc3.metric("Distinct Detectors", ent_row["distinct_detectors_triggered"])

        if len(ent_alerts) > 0:
            st.subheader("Alert Statistics")
            ac1, ac2, ac3 = st.columns(3)
            avg_close = ent_alerts["time_to_close_min"].dropna().mean()
            ac1.metric("Avg Closure Time (min)", f"{avg_close:.0f}" if not np.isnan(avg_close) else "N/A")
            if "escalated" in ent_alerts.columns:
                esc_rate = ent_alerts["escalated"].mean() * 100
                ac2.metric("Escalation Rate", f"{esc_rate:.1f}%")
            ac3.metric("Total Alerts", len(ent_alerts))

            # Severity distribution
            st.subheader("Severity Distribution")
            sev_counts = ent_alerts["severity"].value_counts()
            fig = px.pie(values=sev_counts.values, names=sev_counts.index, hole=0.4)
            fig.update_layout(height=250)
            st.plotly_chart(fig, use_container_width=True)

    with tab_alerts:
        st.subheader("Alert Records")
        display_cols = [c for c in ["alert_id", "severity", "category", "disposition", "created_at", "time_to_close_min"] if c in ent_alerts.columns]
        if display_cols:
            st.dataframe(ent_alerts[display_cols].head(100), use_container_width=True, hide_index=True)
        else:
            st.info("No alert columns available for display.")

    with tab_assets:
        st.subheader("Asset Inventory")
        if len(ent_assets) > 0:
            st.dataframe(ent_assets, use_container_width=True, hide_index=True)
            crit_assets = ent_assets[ent_assets["criticality"] == "critical"]
            if len(crit_assets) > 0:
                st.info(f"{len(crit_assets)} critical assets identified for this entity.")
        else:
            st.info("No assets found for this entity.")

    with tab_findings:
        st.subheader("Entity Findings")
        if len(ent_flags) > 0:
            for _, f in ent_flags.iterrows():
                recur = " [RECURRING]" if f.get("recurring", False) else ""
                with st.expander(
                    f"{render_type_tag(f['detector_type'])} {f['flag_id']} - {f['detector_name']} | {f.get('severity', 'N/A').upper()}{recur}",
                    expanded=False,
                ):
                    st.markdown(f"**Rationale:** {f.get('rationale', 'N/A')}")
                    st.markdown(f"**Confidence:** {f.get('confidence', 'N/A')}")
                    st.markdown(f"**Disposition:** {f.get('disposition', 'pending')}")
                    if f["detector"] == "fast_closure":
                        st.markdown(f"**Observed:** {f.get('observed_value', 'N/A')} min")
                        st.markdown(f"**Baseline Q1:** {f.get('baseline_q1', 'N/A')} min")
                        st.markdown(f"**Threshold:** {f.get('threshold', 'N/A')} min")
                    elif f["detector"] == "low_coverage":
                        st.markdown(f"**Observed:** {f.get('observed_value', 'N/A')} alerts in window")
                        st.markdown(f"**Peer Median:** {f.get('baseline_median', 'N/A')}")
                        st.markdown(f"**Threshold:** {f.get('threshold', 'N/A')}")
        else:
            st.success("No findings for this entity in the current cycle.")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: FINDINGS FEED
# ─────────────────────────────────────────────────────────────────────────────
def page_findings():
    data = st.session_state.pipeline_data
    if data is None:
        st.warning("No data loaded. Please upload data first.")
        return

    flags = data["flags"]
    if not isinstance(flags, pd.DataFrame) or len(flags) == 0:
        st.info("No findings detected in the current dataset.")
        return

    st.title("Findings Feed")
    st.caption(f"Total findings: {len(flags)}")

    # Sidebar filters
    with st.sidebar:
        st.header("Filters")
        f_entity = st.multiselect("Entity", flags["entity_id"].unique().tolist()[:20])
        f_detector = st.multiselect("Detector", flags["detector_name"].unique().tolist())
        f_severity = st.multiselect("Severity", ["critical", "high", "medium", "low"])
        f_type = st.multiselect("Type", ["EG", "NS"])

    filtered = flags.copy()
    if f_entity:
        filtered = filtered[filtered["entity_id"].isin(f_entity)]
    if f_detector:
        filtered = filtered[filtered["detector_name"].isin(f_detector)]
    if f_severity:
        filtered = filtered[filtered["severity"].isin(f_severity)]
    if f_type:
        filtered = filtered[filtered["detector_type"].isin(f_type)]

    # Sort: recurring first, then severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    filtered["_sev_order"] = filtered["severity"].map(sev_order).fillna(4)
    filtered["_recur_order"] = filtered["recurring"].map({True: 0, False: 1}).fillna(1)
    filtered = filtered.sort_values(["_recur_order", "_sev_order"])

    # EG / NS Tabs
    tab_eg, tab_ns = st.tabs(["Execution Gaps (EG)", "Negative Space (NS)"])

    with tab_eg:
        eg_findings = filtered[filtered["detector_type"] == "EG"]
        if len(eg_findings) == 0:
            st.info("No EG findings match current filters.")
        else:
            for _, f in eg_findings.iterrows():
                recur = " [RECURRING]" if f.get("recurring", False) else ""
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([1, 3, 2, 1])
                    with c1:
                        st.markdown(render_severity_pill(f.get("severity", "low")), unsafe_allow_html=True)
                    with c2:
                        st.markdown(f"**{f['flag_id']}** - {f['entity_id']}{recur}")
                        st.caption(f"{f['detector_name']}")
                    with c3:
                        st.caption(f"Confidence: {f.get('confidence', 'N/A')}")
                        st.caption(f"Detected: {f.get('date_detected', 'N/A')}")
                        st.caption(f"Disposition: {f.get('disposition', 'pending')}")
                    with c4:
                        if st.button("View", key=f"eg_{f['flag_id']}", use_container_width=True):
                            st.session_state.active_finding_id = f["flag_id"]

    with tab_ns:
        ns_findings = filtered[filtered["detector_type"] == "NS"]
        if len(ns_findings) == 0:
            st.info("No NS findings match current filters.")
        else:
            for _, f in ns_findings.iterrows():
                recur = " [RECURRING]" if f.get("recurring", False) else ""
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([1, 3, 2, 1])
                    with c1:
                        st.markdown(render_severity_pill(f.get("severity", "low")), unsafe_allow_html=True)
                    with c2:
                        st.markdown(f"**{f['flag_id']}** - {f['entity_id']}{recur}")
                        st.caption(f"{f['detector_name']}")
                    with c3:
                        st.caption(f"Confidence: {f.get('confidence', 'N/A')}")
                        st.caption(f"Detected: {f.get('date_detected', 'N/A')}")
                        st.caption(f"Disposition: {f.get('disposition', 'pending')}")
                    with c4:
                        if st.button("View", key=f"ns_{f['flag_id']}", use_container_width=True):
                            st.session_state.active_finding_id = f["flag_id"]

    # Finding detail
    if st.session_state.active_finding_id:
        st.divider()
        _render_finding_detail(st.session_state.active_finding_id)


def _render_finding_detail(finding_id):
    data = st.session_state.pipeline_data
    flags = data["flags"]
    f_row = flags[flags["flag_id"] == finding_id]

    if len(f_row) == 0:
        st.error("Finding not found.")
        return

    f = f_row.iloc[0]
    st.subheader(f"Finding Detail: {f['flag_id']}")

    type_tag = "EG" if f["detector_type"] == "EG" else "NS"
    st.markdown(
        f'<div class="finding-statement">'
        f'{render_type_tag(type_tag)} '
        f'{render_severity_pill(f.get("severity", "low"))} '
        f' - {f["detector_name"]} flagged for <b>{f["entity_id"]}</b>'
        f'</div>',
        unsafe_allow_html=True,
    )

    with st.expander("Why This Fired", expanded=True):
        st.markdown(f"**Detector:** {f['detector_name']}")
        st.markdown(f"**Rationale:** {f.get('rationale', 'N/A')}")
        if f["detector"] == "fast_closure":
            st.markdown(f"**Observed:** {f.get('observed_value', 'N/A')} min")
            st.markdown(f"**Baseline Q1:** {f.get('baseline_q1', 'N/A')} min")
            st.markdown(f"**Baseline IQR:** {f.get('baseline_iqr', 'N/A')} min")
            st.markdown(f"**Threshold (Q1 - 1.5*IQR):** {f.get('threshold', 'N/A')} min")
        elif f["detector"] == "no_escalation":
            st.markdown(f"**Condition:** severity=critical AND disposition=true_positive AND escalated=false")
        elif f["detector"] == "low_coverage":
            st.markdown(f"**Observed Count:** {f.get('observed_value', 'N/A')}")
            st.markdown(f"**Peer Median:** {f.get('baseline_median', 'N/A')}")
            st.markdown(f"**Threshold (25% of median):** {f.get('threshold', 'N/A')}")

    with st.expander("Evidence"):
        st.markdown(f"**Alert/Asset ID:** {f.get('alert_id', f.get('asset_id', 'N/A'))}")
        st.markdown(f"**Entity:** {f['entity_id']}")
        st.markdown(f"**Detection Date:** {f.get('date_detected', 'N/A')}")
        st.markdown(f"**Confidence:** {f.get('confidence', 'N/A')}")

    # Disposition
    st.divider()
    st.subheader("Disposition")
    d1, d2 = st.columns([2, 1])
    with d1:
        disp_choice = st.radio(
            "Disposition",
            ["Reviewed - Benign", "Confirmed - Escalate", "Insufficient Evidence"],
            horizontal=True,
            key=f"disp_{finding_id}",
        )
        note = st.text_area("Examiner Note", key=f"note_{finding_id}")
    with d2:
        st.write("")
        st.write("")
        if st.button("Save Disposition", type="primary", key=f"save_{finding_id}"):
            st.session_state.dispositions[finding_id] = {
                "disposition": disp_choice,
                "note": note,
                "examiner": "Current User",
                "timestamp": datetime.now().isoformat(),
            }
            st.success(f"Disposition saved for {finding_id}")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: PEER BENCHMARKING
# ─────────────────────────────────────────────────────────────────────────────
def page_benchmarking():
    data = st.session_state.pipeline_data
    if data is None:
        st.warning("No data loaded. Please upload data first.")
        return

    scores = data["scores"]
    if len(scores) == 0:
        st.info("No scored entities available.")
        return

    st.title("Peer Benchmarking")
    st.caption("Compare entity metrics against peer group distributions.")

    c1, c2, c3 = st.columns(3)
    with c1:
        pg_options = scores["peer_group"].dropna().unique().tolist() if "peer_group" in scores.columns else []
        selected_pg = st.selectbox("Peer Group", pg_options if pg_options else ["All"])
    with c2:
        metric = st.selectbox("Metric", ["risk_score", "eg_count", "ns_count", "alert_volume"])
    with c3:
        pg_entities = scores[scores["peer_group"] == selected_pg] if selected_pg != "All" and "peer_group" in scores.columns else scores
        selected_entity = st.selectbox("Highlight Entity", pg_entities["entity_id"].tolist())

    pg_data = scores[scores["peer_group"] == selected_pg] if selected_pg != "All" and "peer_group" in scores.columns else scores

    # Violin plot
    fig = go.Figure()
    fig.add_trace(go.Violin(
        y=pg_data[metric],
        name="Peer Distribution",
        box_visible=True,
        meanline_visible=True,
        fillcolor="#1565c033",
        line_color="#1565c0",
        points="all",
        jitter=0.3,
        pointpos=-1.5,
    ))

    ent_val = pg_data[pg_data["entity_id"] == selected_entity][metric].values
    if len(ent_val) > 0:
        fig.add_trace(go.Scatter(
            y=ent_val,
            x=[selected_entity],
            mode="markers",
            marker=dict(size=14, color="#d32f2f", symbol="diamond"),
            name=selected_entity,
        ))

    fig.update_layout(
        height=350,
        title=f"{metric.replace('_', ' ').title()} - {selected_pg}",
        yaxis_title=metric.replace("_", " ").title(),
    )
    st.plotly_chart(fig, use_container_width=True)

    # Ranked table
    st.subheader("Peer Group Ranking")
    ranked = pg_data.sort_values(metric, ascending=False)[["entity_id", "name", metric, "risk_score"]].reset_index(drop=True)
    ranked.index += 1
    ranked.columns = ["Rank", "Entity ID", "Name", "Metric Value", "Risk Score"]
    st.dataframe(ranked, use_container_width=True)

    if len(ent_val) > 0:
        percentile = (pg_data[metric] < ent_val[0]).mean() * 100
        st.info(f"{selected_entity} is at the {percentile:.0f}th percentile for {metric} in {selected_pg}.")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: DATA HEALTH
# ─────────────────────────────────────────────────────────────────────────────
def page_data_health():
    data = st.session_state.pipeline_data
    if data is None:
        st.warning("No data loaded. Please upload data first.")
        return

    submissions = data["submissions"]
    categories = data["categories"]

    st.title("Data Health / Submissions")
    st.caption("Distinguishing 'did not submit' (compliance issue) from 'submitted but sparse' (negative-space candidate).")

    # Build matrix
    pivot = submissions.pivot_table(
        index="entity_id", columns="category", values="status", aggfunc="first"
    ).reset_index()

    # Display
    color_map = {"submitted": "OK", "sparse": "PARTIAL", "not_submitted": "MISSING"}
    display_pivot = pivot.copy()
    for cat in categories:
        if cat in display_pivot.columns:
            display_pivot[cat] = display_pivot[cat].map(color_map).fillna("N/A")

    st.dataframe(display_pivot, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("**Legend:** OK = Submitted & Complete | PARTIAL = Submitted & Sparse | MISSING = Not Submitted")

    # Summary
    total_cells = len(submissions)
    ok_cells = len(submissions[submissions["status"] == "submitted"])
    sparse_cells = len(submissions[submissions["status"] == "sparse"])
    missing_cells = len(submissions[submissions["status"] == "not_submitted"])

    c1, c2, c3 = st.columns(3)
    c1.metric("Complete", ok_cells, delta=f"{ok_cells/total_cells*100:.0f}%")
    c2.metric("Sparse", sparse_cells, delta=f"{sparse_cells/total_cells*100:.0f}%")
    c3.metric("Missing", missing_cells, delta=f"{missing_cells/total_cells*100:.0f}%")

    sparse_entities = submissions[submissions["status"] == "sparse"]["entity_id"].unique()
    if len(sparse_entities) > 0:
        st.info(f"{len(sparse_entities)} entities have sparse submissions - these are negative-space candidates.")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: DETECTOR LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
def page_detector_library():
    data = st.session_state.pipeline_data

    st.title("Detector Library")
    st.caption("Explainability and auditability of the detection rule set.")

    detectors = pd.DataFrame([
        {
            "Rule ID": "D1-FC-001",
            "Description": "High/critical alerts closed faster than Q1 - 1.5*IQR for that severity",
            "Method": "Q1 - 1.5*IQR lower fence",
            "Threshold": "k = 1.5",
            "Type": "EG",
            "Capability Area": "Operational Discipline",
        },
        {
            "Rule ID": "D2-NE-001",
            "Description": "Critical true-positive alert closed without recorded escalation",
            "Method": "Deterministic rule",
            "Threshold": "severity=critical AND disposition=true_positive AND escalated=false",
            "Type": "EG",
            "Capability Area": "Escalation",
        },
        {
            "Rule ID": "D3-LC-001",
            "Description": "Critical asset with 30-day alert count below 25% of peer median",
            "Method": "Peer-relative threshold",
            "Threshold": "count < 0.25 * peer_median",
            "Type": "NS",
            "Capability Area": "Detection",
        },
    ])

    st.dataframe(detectors, use_container_width=True, hide_index=True)

    if data is not None and isinstance(data["flags"], pd.DataFrame) and len(data["flags"]) > 0:
        st.divider()
        st.subheader("Fired This Cycle")
        det_counts = data["flags"]["detector_name"].value_counts().reset_index()
        det_counts.columns = ["Detector", "Count"]
        st.dataframe(det_counts, use_container_width=True, hide_index=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: REPORT CENTER
# ─────────────────────────────────────────────────────────────────────────────
def page_reports():
    data = st.session_state.pipeline_data
    if data is None:
        st.warning("No data loaded. Please upload data first.")
        return

    scores = data["scores"]
    flags = data["flags"]

    st.title("Report Center")
    st.caption("Generate reports from reviewed data.")

    c1, c2 = st.columns(2)
    with c1:
        report_type = st.selectbox(
            "Report Type",
            ["Portfolio Summary", "Entity Assessment", "Findings Export (CSV)"],
        )
    with c2:
        if report_type == "Entity Assessment":
            entity_sel = st.selectbox("Entity", scores["entity_id"].tolist())
        else:
            entity_sel = None

    st.divider()
    st.subheader("Report Preview")

    if report_type == "Portfolio Summary":
        st.markdown(f"### Portfolio Summary - {st.session_state.active_cycle}")
        st.markdown(f"- **Entities Assessed:** {len(scores)}")
        st.markdown(f"- **Total Findings:** {len(flags) if isinstance(flags, pd.DataFrame) else 0}")
        if isinstance(flags, pd.DataFrame) and len(flags) > 0:
            eg_count = len(flags[flags["detector_type"] == "EG"])
            ns_count = len(flags[flags["detector_type"] == "NS"])
            st.markdown(f"- **EG Findings:** {eg_count}")
            st.markdown(f"- **NS Findings:** {ns_count}")
        st.markdown(f"- **Average Risk Score:** {scores['risk_score'].mean():.2f}")

        st.markdown("#### Top 5 Entities by Risk")
        top5 = scores.nlargest(5, "risk_score")[["entity_id", "name", "risk_score"]]
        st.dataframe(top5, use_container_width=True, hide_index=True)

    elif report_type == "Entity Assessment" and entity_sel:
        ent = scores[scores["entity_id"] == entity_sel].iloc[0]
        ent_flags = flags[flags["entity_id"] == entity_sel] if isinstance(flags, pd.DataFrame) else pd.DataFrame()
        st.markdown(f"### Entity Assessment: {ent.get('name', entity_sel)} ({entity_sel})")
        st.markdown(f"- **Peer Group:** {ent.get('peer_group', 'N/A')}")
        st.markdown(f"- **Risk Score:** {ent['risk_score']:.2f}")
        st.markdown(f"- **Priority Rank:** #{ent['priority_rank']}")
        st.markdown(f"- **Total Findings:** {len(ent_flags)}")

    elif report_type == "Findings Export (CSV)":
        if isinstance(flags, pd.DataFrame) and len(flags) > 0:
            export_cols = [c for c in ["flag_id", "entity_id", "detector_name", "severity", "detector_type", "disposition"] if c in flags.columns]
            st.dataframe(flags[export_cols].head(20), use_container_width=True, hide_index=True)
            st.caption(f"Showing {min(20, len(flags))} of {len(flags)} findings")
        else:
            st.info("No findings to export.")

    st.divider()
    st.subheader("Export")

    if report_type == "Findings Export (CSV)":
        if isinstance(flags, pd.DataFrame) and len(flags) > 0:
            csv_data = flags.to_csv(index=False)
            st.download_button(
                "Download Findings CSV",
                data=csv_data,
                file_name=f"satsa_findings_{st.session_state.active_cycle}.csv",
                mime="text/csv",
                type="primary",
            )
    else:
        report_json = {
            "generated_at": datetime.now().isoformat(),
            "cycle": st.session_state.active_cycle,
            "report_type": report_type,
            "entity": entity_sel,
            "summary": {
                "total_entities": len(scores),
                "total_findings": len(flags) if isinstance(flags, pd.DataFrame) else 0,
            },
        }
        st.download_button(
            "Download Report (JSON)",
            data=json.dumps(report_json, indent=2),
            file_name=f"satsa_report_{st.session_state.active_cycle}.json",
            mime="application/json",
            type="primary",
        )


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: REVIEW QUEUE
# ─────────────────────────────────────────────────────────────────────────────
def page_review_queue():
    data = st.session_state.pipeline_data
    if data is None:
        st.warning("No data loaded. Please upload data first.")
        return

    flags = data["flags"]
    if not isinstance(flags, pd.DataFrame) or len(flags) == 0:
        st.info("No findings to review.")
        return

    st.title("Review Queue")
    st.caption("Prioritized items requiring examiner attention.")

    pending = flags[flags["disposition"] == "pending"].copy()
    if len(pending) == 0:
        st.success("Queue is clear. No pending items.")
        return

    # Priority score: severity weight * confidence * recurrence multiplier
    sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    pending["priority_score"] = (
        pending["severity"].map(sev_weight).fillna(1)
        * pending.get("confidence", pd.Series([0.8]*len(pending)))
        * pending.get("recurring", pd.Series([False]*len(pending))).map({True: 1.5, False: 1.0})
    )
    pending = pending.sort_values("priority_score", ascending=False)

    qm1, qm2 = st.columns(2)
    qm1.metric("Pending Items", len(pending))
    qm2.metric("Completed", len(flags) - len(pending))

    st.divider()

    for _, item in pending.head(25).iterrows():
        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([1, 4, 2, 2])
            with c1:
                st.markdown(f"**{item['priority_score']:.1f}**")
            with c2:
                st.markdown(f"**{item['flag_id']}** - {item['entity_id']}")
                st.caption(f"{item['detector_name']} | {item.get('severity', 'N/A')}")
            with c3:
                new_status = st.selectbox(
                    "Status",
                    ["To Review", "In Progress", "Done"],
                    key=f"status_{item['flag_id']}",
                    label_visibility="collapsed",
                )
            with c4:
                st.text_input(
                    "Assignee",
                    value="",
                    key=f"assign_{item['flag_id']}",
                    label_visibility="collapsed",
                    placeholder="Assign to...",
                )


# ─────────────────────────────────────────────────────────────────────────────
# NAVIGATION
# ─────────────────────────────────────────────────────────────────────────────
upload_page = st.Page(page_upload, title="Upload Data", default=True)
portfolio_page = st.Page(page_portfolio, title="Portfolio")
entity_page = st.Page(page_entity_profile, title="Entity Profile")
findings_page = st.Page(page_findings, title="Findings")
benchmark_page = st.Page(page_benchmarking, title="Peer Benchmarking")
queue_page = st.Page(page_review_queue, title="Review Queue")
health_page = st.Page(page_data_health, title="Data Health")
detector_page = st.Page(page_detector_library, title="Detector Library")
reports_page = st.Page(page_reports, title="Reports")

# Only show analysis pages if data is loaded
if st.session_state.pipeline_data is not None:
    pg = st.navigation({
        "Data": [upload_page],
        "Analysis": [portfolio_page, entity_page, findings_page, benchmark_page],
        "Operations": [queue_page, health_page],
        "Audit": [detector_page, reports_page],
    })
else:
    pg = st.navigation({
        "Data": [upload_page],
    })

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## SAT-SA")
    st.caption("Supervisory Analytics Tool for SOC Assessment")
    st.divider()

    cycle = st.selectbox(
        "Assessment Cycle",
        ["2025-Q3", "2025-Q2", "2025-Q1", "2024-Q4"],
        index=0,
    )
    st.session_state.active_cycle = cycle

    st.divider()

    # Pipeline status
    if st.session_state.pipeline_data is not None:
        st.markdown('<span class="status-ready">Pipeline: Complete</span>', unsafe_allow_html=True)
        d = st.session_state.pipeline_data
        st.caption(f"Entities: {len(d['entities'])}")
        st.caption(f"Alerts: {len(d['alerts'])}")
        st.caption(f"Flags: {len(d['flags']) if isinstance(d['flags'], pd.DataFrame) else 0}")
    else:
        st.markdown('<span class="status-pending">Pipeline: Awaiting Data</span>', unsafe_allow_html=True)

    st.divider()
    st.caption("SAT-SA v1.0")
    st.caption(f"{datetime.now().strftime('%Y-%m-%d %H:%M')}")
    st.caption("Offline / Air-gapped")


# ─────────────────────────────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────────────────────────────
pg.run()
