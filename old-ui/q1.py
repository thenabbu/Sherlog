"""
SAT-SA — Supervisor Interface (v1)
Streamlit multipage dashboard for NCIIPC examiners.
Run: streamlit run app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import json
import hashlib
import random

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SAT-SA Supervisor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: var(--secondary-background-color);
        border-radius: 10px;
        padding: 1rem;
        border-left: 4px solid var(--primary-color);
    }
    .risk-critical { color: #ff4b4b; font-weight: bold; }
    .risk-high { color: #ffa421; font-weight: bold; }
    .risk-medium { color: #faca2b; font-weight: bold; }
    .risk-low { color: #21c354; font-weight: bold; }
    .tag-eg {
        background: #ff4b4b; color: white; padding: 2px 8px;
        border-radius: 12px; font-size: 0.75em; font-weight: bold;
    }
    .tag-ns {
        background: #1c83e1; color: white; padding: 2px 8px;
        border-radius: 12px; font-size: 0.75em; font-weight: bold;
    }
    .recurrence-badge {
        background: #ffa421; color: white; padding: 2px 6px;
        border-radius: 8px; font-size: 0.7em;
    }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 8px 16px;
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
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# SYNTHETIC DATA GENERATION (simulates CLI output artifacts)
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_data
def generate_synthetic_data():
    """Generate realistic synthetic data mimicking SAT-SA CLI output."""
    np.random.seed(42)
    random.seed(42)

    # --- Entities (CSEs) ---
    n_entities = 25
    sectors = ["Financial Services", "Energy", "Telecommunications",
               "Transportation", "Healthcare", "Water Utilities"]
    peer_groups = ["finserv-tier2", "energy-tier2", "telecom-tier2",
                   "transport-tier2", "health-tier2", "water-tier2"]

    entities = []
    for i in range(n_entities):
        sector_idx = i % len(sectors)
        entities.append({
            "entity_id": f"CSE-{i+1:03d}",
            "name": f"{sectors[sector_idx].split()[0]} Entity {i+1:03d}",
            "sector": sectors[sector_idx],
            "peer_group": peer_groups[sector_idx],
            "submission_status": random.choice(
                ["submitted", "submitted", "submitted", "submitted",
                 "submitted", "sparse", "not_submitted"]
            ),
        })

    # --- Alerts ---
    alerts = []
    alert_id_counter = 1
    for ent in entities:
        n_alerts = random.randint(50, 400)
        for _ in range(n_alerts):
            severity = random.choices(
                ["critical", "high", "medium", "low"],
                weights=[0.35, 0.35, 0.22, 0.08]
            )[0]
            disposition = random.choices(
                ["true_positive", "false_positive", "benign", "unresolved"],
                weights=[0.22, 0.35, 0.35, 0.08]
            )[0]
            category = random.choice(["malware", "intrusion", "phishing", "DoS"])
            created = datetime(2025, 6, 1) + timedelta(
                hours=random.randint(0, 2000)
            )
            closed = created + timedelta(minutes=random.randint(5, 2880))
            escalated = random.random() > 0.7

            alerts.append({
                "alert_id": f"AL-{alert_id_counter:06d}",
                "entity_id": ent["entity_id"],
                "asset_id": f"AST-{ent['entity_id'][-3:]}-{random.randint(1,3)}",
                "category": category,
                "severity": severity,
                "created_at": created.isoformat(),
                "closed_at": closed.isoformat(),
                "disposition": disposition,
                "escalated": escalated,
                "time_to_close_min": (closed - created).total_seconds() / 60,
            })
            alert_id_counter += 1

    alerts_df = pd.DataFrame(alerts)

    # --- Assets ---
    assets = []
    for ent in entities:
        for j in range(1, 4):
            assets.append({
                "asset_id": f"AST-{ent['entity_id'][-3:]}-{j}",
                "entity_id": ent["entity_id"],
                "criticality": random.choices(
                    ["critical", "high", "medium", "low"],
                    weights=[0.3, 0.3, 0.25, 0.15]
                )[0],
                "asset_type": random.choice(
                    ["SCADA", "PLC", "HMI", "Firewall", "IDS", "Server"]
                ),
                "telemetry_status": random.choices(
                    ["active", "degraded", "silent"],
                    weights=[0.7, 0.2, 0.1]
                )[0],
            })
    assets_df = pd.DataFrame(assets)

    # --- Findings (simulated detector output) ---
    findings = []
    finding_id_counter = 1
    capability_areas = [
        "Detection", "Investigation", "Escalation", "Incident Response",
        "Security Operations", "Governance & Oversight",
        "Operational Discipline", "Cyber Resilience"
    ]

    detector_rules = {
        "fast_closure": {
            "name": "D1 — Fast Closure",
            "type": "EG",
            "method": "Q1 − 1.5×IQR lower fence",
            "capability": "Operational Discipline",
        },
        "no_escalation": {
            "name": "D2 — Critical TP No Escalation",
            "type": "EG",
            "method": "Deterministic rule",
            "capability": "Escalation",
        },
        "low_coverage": {
            "name": "D3 — Low Critical-Asset Coverage",
            "type": "NS",
            "method": "30-day count < 25% peer median",
            "capability": "Detection",
        },
    }

    for ent in entities:
        n_findings = random.randint(0, 8)
        for _ in range(n_findings):
            det_key = random.choice(list(detector_rules.keys()))
            det = detector_rules[det_key]
            severity = random.choices(
                ["critical", "high", "medium", "low"],
                weights=[0.2, 0.3, 0.3, 0.2]
            )[0]
            findings.append({
                "finding_id": f"FG-{finding_id_counter:05d}",
                "entity_id": ent["entity_id"],
                "entity_name": ent["name"],
                "sector": ent["sector"],
                "detector": det_key,
                "detector_name": det["name"],
                "detector_type": det["type"],
                "method": det["method"],
                "capability_area": det["capability"],
                "severity": severity,
                "confidence": round(random.uniform(0.6, 0.99), 2),
                "date_detected": (
                    datetime(2025, 6, 1) + timedelta(days=random.randint(0, 90))
                ).strftime("%Y-%m-%d"),
                "disposition": random.choice(
                    ["pending", "pending", "reviewed_benign",
                     "confirmed_escalate", "insufficient_evidence"]
                ),
                "recurring": random.random() > 0.75,
                "observed_value": round(random.uniform(1, 500), 1),
                "baseline_value": round(random.uniform(50, 1000), 1),
                "threshold": round(random.uniform(10, 200), 1),
            })
            finding_id_counter += 1

    findings_df = pd.DataFrame(findings)

    # --- Entity Scores ---
    scores = []
    weights = {"fast_closure": 2, "no_escalation": 3, "low_coverage": 2}
    for ent in entities:
        ent_findings = findings_df[findings_df["entity_id"] == ent["entity_id"]]
        alert_vol = len(alerts_df[alerts_df["entity_id"] == ent["entity_id"]])

        numerator = sum(
            weights.get(f, 0)
            for f in ent_findings["detector"].tolist()
        )
        risk_score = numerator / np.log(1 + max(alert_vol, 1)) if alert_vol > 0 else numerator

        eg_count = len(ent_findings[ent_findings["detector_type"] == "EG"])
        ns_count = len(ent_findings[ent_findings["detector_type"] == "NS"])

        scores.append({
            "entity_id": ent["entity_id"],
            "name": ent["name"],
            "sector": ent["sector"],
            "peer_group": ent["peer_group"],
            "risk_score": round(risk_score, 4),
            "eg_count": eg_count,
            "ns_count": ns_count,
            "alert_volume": alert_vol,
            "submission_status": ent["submission_status"],
            "trend": [round(risk_score * random.uniform(0.6, 1.4), 2) for _ in range(4)],
        })

    scores_df = pd.DataFrame(scores)
    scores_df = scores_df.sort_values("risk_score", ascending=False).reset_index(drop=True)
    scores_df["priority_rank"] = range(1, len(scores_df) + 1)

    # --- Review Queue ---
    queue_items = []
    for f in findings_df[findings_df["disposition"] == "pending"].head(20).itertuples():
        queue_items.append({
            "item_id": f.finding_id,
            "type": "finding",
            "entity_id": f.entity_id,
            "entity_name": f.entity_name,
            "reason": f"{f.detector_name} — {f.severity} severity, confidence {f.confidence}",
            "priority_score": round(
                {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 1)
                * f.confidence * (1.5 if f.recurring else 1.0), 2
            ),
            "status": random.choice(["To review", "To review", "In progress"]),
            "assignee": random.choice(["Examiner A", "Examiner B", ""]),
        })
    queue_df = pd.DataFrame(queue_items)
    if not queue_df.empty:
        queue_df = queue_df.sort_values("priority_score", ascending=False)

    # --- Submissions Matrix ---
    categories = [
        "Alert Metadata", "Case Management", "Investigation Workflow",
        "Escalation Records", "Disposition & Closure", "Asset Inventory"
    ]
    submissions = []
    for ent in entities:
        for cat in categories:
            if ent["submission_status"] == "not_submitted":
                status = "not_submitted"
            elif ent["submission_status"] == "sparse":
                status = random.choice(["submitted", "sparse", "sparse"])
            else:
                status = random.choices(
                    ["submitted", "sparse"], weights=[0.85, 0.15]
                )[0]
            submissions.append({
                "entity_id": ent["entity_id"],
                "name": ent["name"],
                "category": cat,
                "status": status,
            })
    submissions_df = pd.DataFrame(submissions)

    # --- Detector Library ---
    detectors_df = pd.DataFrame([
        {
            "rule_id": "D1-FC-001",
            "description": "High/critical alerts closed faster than Q1 − 1.5×IQR for that severity",
            "method": "Q1 − 1.5×IQR lower fence",
            "threshold": "k = 1.5",
            "capability_area": "Operational Discipline",
            "type": "EG",
            "last_calibrated": "2025-08-01",
            "fired_this_cycle": len(findings_df[findings_df["detector"] == "fast_closure"]),
        },
        {
            "rule_id": "D2-NE-001",
            "description": "Critical true-positive alert closed without recorded escalation",
            "method": "Deterministic rule",
            "threshold": "severity=critical ∧ disposition=true_positive ∧ escalated=false",
            "capability_area": "Escalation",
            "type": "EG",
            "last_calibrated": "2025-08-01",
            "fired_this_cycle": len(findings_df[findings_df["detector"] == "no_escalation"]),
        },
        {
            "rule_id": "D3-LC-001",
            "description": "Critical asset with 30-day alert count < 25% of peer median",
            "method": "Peer-relative threshold",
            "threshold": "count < 0.25 × peer_median",
            "capability_area": "Detection",
            "type": "NS",
            "last_calibrated": "2025-08-01",
            "fired_this_cycle": len(findings_df[findings_df["detector"] == "low_coverage"]),
        },
    ])

    return {
        "entities": pd.DataFrame(entities),
        "alerts": alerts_df,
        "assets": assets_df,
        "findings": findings_df,
        "scores": scores_df,
        "queue": queue_df,
        "submissions": submissions_df,
        "detectors": detectors_df,
        "categories": categories,
        "capability_areas": capability_areas,
    }


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def risk_color(score):
    """Return color based on risk score thresholds."""
    if score >= 3.0:
        return "#ff4b4b"
    elif score >= 1.5:
        return "#ffa421"
    elif score >= 0.5:
        return "#faca2b"
    return "#21c354"


def severity_color(sev):
    """Return color for severity level."""
    return {
        "critical": "#ff4b4b",
        "high": "#ffa421",
        "medium": "#faca2b",
        "low": "#21c354",
    }.get(sev, "#a3a8b8")


def status_icon(status):
    """Return icon for submission status."""
    return {
        "submitted": "✅",
        "sparse": "⚠️",
        "not_submitted": "❌",
    }.get(status, "❓")


def disposition_icon(disp):
    """Return icon for disposition status."""
    return {
        "pending": "🔶",
        "reviewed_benign": "✅",
        "confirmed_escalate": "🚨",
        "insufficient_evidence": "❓",
    }.get(disp, "⬜")


def render_type_tag(det_type):
    """Render EG/NS tag."""
    if det_type == "EG":
        return '<span class="tag-eg">EG</span>'
    return '<span class="tag-ns">NS</span>'


def render_severity_pill(severity):
    """Render severity as colored pill."""
    color = severity_color(severity)
    return f'<span style="background:{color};color:white;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:bold;">{severity.upper()}</span>'


def render_recurrence(is_recurring):
    """Render recurrence badge."""
    if is_recurring:
        return '<span class="recurrence-badge">🔄 RECUR</span>'
    return ""


def make_sparkline(data, color="#1c83e1"):
    """Create a mini sparkline figure."""
    fig = go.Figure(go.Scatter(
        y=data, mode="lines",
        line=dict(color=color, width=2),
        hoverinfo="skip",
    ))
    fig.update_layout(
        height=40, margin=dict(l=0, r=0, t=0, b=0),
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────────

if "data" not in st.session_state:
    st.session_state.data = generate_synthetic_data()

if "active_entity_id" not in st.session_state:
    st.session_state.active_entity_id = None

if "active_finding_id" not in st.session_state:
    st.session_state.active_finding_id = None

if "active_cycle" not in st.session_state:
    st.session_state.active_cycle = "2025-Q3"

if "nav_history" not in st.session_state:
    st.session_state.nav_history = ["Portfolio"]

if "queue_updates" not in st.session_state:
    st.session_state.queue_updates = {}

if "dispositions" not in st.session_state:
    st.session_state.dispositions = {}


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1: PORTFOLIO OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────

def page_portfolio():
    """Portfolio overview — triage across the whole CSE portfolio."""
    data = st.session_state.data
    scores = data["scores"]

    st.title("🛡️ Portfolio Overview")
    st.caption(f"Cycle: **{st.session_state.active_cycle}** — Supervisory triage across all Critical Sector Entities")

    # --- Top Metrics Strip ---
    col1, col2, col3, col4, col5 = st.columns(5)

    total_assessed = len(scores[scores["submission_status"] != "not_submitted"])
    eg_flagged = len(scores[scores["eg_count"] > 0])
    ns_flagged = len(scores[scores["ns_count"] > 0])
    no_sub = len(scores[scores["submission_status"] == "not_submitted"])
    avg_risk = scores["risk_score"].mean()

    col1.metric("CSEs Assessed", total_assessed, delta=f"of {len(scores)}")
    col2.metric("Flagged (EG)", eg_flagged, delta=f"{eg_flagged/len(scores)*100:.0f}%", delta_color="inverse")
    col3.metric("Flagged (NS)", ns_flagged, delta=f"{ns_flagged/len(scores)*100:.0f}%", delta_color="inverse")
    col4.metric("No Submission", no_sub, delta_color="inverse")
    col5.metric("Avg Portfolio Risk", f"{avg_risk:.2f}", delta="+0.12", delta_color="inverse")

    st.divider()

    # --- Filter Row ---
    with st.container():
        fc1, fc2, fc3, fc4 = st.columns([2, 2, 1, 1])
        with fc1:
            sector_filter = st.multiselect(
                "Sector",
                options=scores["sector"].unique().tolist(),
                placeholder="All sectors",
            )
        with fc2:
            min_risk = st.slider("Min Risk Score", 0.0, 5.0, 0.0, 0.1)
        with fc3:
            new_only = st.toggle("New this cycle")
        with fc4:
            sub_filter = st.selectbox(
                "Submission",
                ["All", "Submitted", "Sparse", "Not Submitted"],
            )

    # Apply filters
    filtered = scores.copy()
    if sector_filter:
        filtered = filtered[filtered["sector"].isin(sector_filter)]
    filtered = filtered[filtered["risk_score"] >= min_risk]
    if sub_filter != "All":
        status_map = {"Submitted": "submitted", "Sparse": "sparse", "Not Submitted": "not_submitted"}
        filtered = filtered[filtered["submission_status"] == status_map[sub_filter]]

    # --- Action Buttons ---
    bc1, bc2, bc3 = st.columns([1, 1, 2])
    with bc1:
        if st.button("📋 View All Findings", use_container_width=True):
            st.session_state.nav_history.append("Findings")
            st.switch_page("portfolio")  # handled via navigation
    with bc2:
        if st.button("📊 Portfolio Report", use_container_width=True):
            st.session_state.nav_history.append("Reports")

    st.divider()

    # --- Main Entity Table ---
    st.subheader("Entity Risk Ranking")

    display_df = filtered[["priority_rank", "name", "sector", "risk_score",
                           "eg_count", "ns_count", "alert_volume",
                           "submission_status"]].copy()
    display_df.columns = ["Rank", "Entity", "Sector", "Risk Score",
                          "EG Flags", "NS Flags", "Alerts", "Submission"]
    display_df["Submission"] = display_df["Submission"].map(status_icon)

    event = st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score",
                min_value=0,
                max_value=5,
                format="%.2f",
            ),
            "EG Flags": st.column_config.NumberColumn("EG Flags", format="%d"),
            "NS Flags": st.column_config.NumberColumn("NS Flags", format="%d"),
        },
        on_select="rerun",
        selection_mode="single-row",
    )

    if event.selection and event.selection.rows:
        row_idx = event.selection.rows[0]
        selected_entity = filtered.iloc[row_idx]
        st.session_state.active_entity_id = selected_entity["entity_id"]
        st.info(
            f"Selected: **{selected_entity['name']}** ({selected_entity['entity_id']}) — "
            f"Risk: {selected_entity['risk_score']:.2f} | "
            f"EG: {selected_entity['eg_count']} | NS: {selected_entity['ns_count']}"
        )
        if st.button("→ Open Entity Profile", type="primary"):
            st.session_state.nav_history.append("Entity Profile")
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2: ENTITY PROFILE
# ─────────────────────────────────────────────────────────────────────────────

def page_entity_profile():
    """Full drill-down on one CSE."""
    data = st.session_state.data
    scores = data["scores"]
    alerts = data["alerts"]
    assets = data["assets"]
    findings = data["findings"]

    entity_id = st.session_state.active_entity_id

    if entity_id is None:
        entity_id = st.selectbox(
            "Select Entity",
            options=scores["entity_id"].tolist(),
            format_func=lambda x: f"{x} — {scores[scores['entity_id']==x]['name'].iloc[0]}",
        )
        st.session_state.active_entity_id = entity_id

    ent_row = scores[scores["entity_id"] == entity_id].iloc[0]
    ent_alerts = alerts[alerts["entity_id"] == entity_id]
    ent_assets = assets[assets["entity_id"] == entity_id]
    ent_findings = findings[findings["entity_id"] == entity_id]

    # --- Header ---
    hcol1, hcol2, hcol3, hcol4 = st.columns([3, 1, 1, 1])
    with hcol1:
        st.title(f"🏢 {ent_row['name']}")
        st.caption(f"**{entity_id}** | Sector: {ent_row['sector']} | Peer Group: {ent_row['peer_group']}")
    with hcol2:
        risk_val = ent_row["risk_score"]
        st.metric("Risk Score", f"{risk_val:.2f}")
    with hcol3:
        st.metric("Priority Rank", f"#{ent_row['priority_rank']}")
    with hcol4:
        st.metric("Alert Volume", ent_row["alert_volume"])

    # Risk badge
    color = risk_color(risk_val)
    st.markdown(
        f'<div style="background:{color}22;border-left:4px solid {color};'
        f'padding:8px 16px;border-radius:4px;margin-bottom:16px;">'
        f'<b>Risk Level:</b> {"CRITICAL" if risk_val >= 3 else "HIGH" if risk_val >= 1.5 else "MEDIUM" if risk_val >= 0.5 else "LOW"}'
        f'</div>',
        unsafe_allow_html=True,
    )

    # --- Tabs ---
    tab_overview, tab_alerts, tab_coverage, tab_findings, tab_history = st.tabs(
        ["📊 Overview", "🚨 Alerts & Cases", "📡 Coverage", "🔍 Findings", "📈 History"]
    )

    with tab_overview:
        st.subheader("Score Composition")
        sc1, sc2, sc3, sc4 = st.columns(4)
        sc1.metric("EG Flags", ent_row["eg_count"])
        sc2.metric("NS Flags", ent_row["ns_count"])
        sc3.metric("Alert Volume", ent_row["alert_volume"])
        sc4.metric("Submission", status_icon(ent_row["submission_status"]))

        # Bar chart of score components
        fig = go.Figure(go.Bar(
            x=["EG Flags", "NS Flags", "Alert Volume (norm)", "Risk Score"],
            y=[
                ent_row["eg_count"],
                ent_row["ns_count"],
                ent_row["alert_volume"] / 50,
                ent_row["risk_score"],
            ],
            marker_color=["#ff4b4b", "#1c83e1", "#ffa421", "#21c354"],
        ))
        fig.update_layout(height=300, margin=dict(t=20, b=20))
        st.plotly_chart(fig, use_container_width=True)

        # Alert stats
        st.subheader("Alert Statistics")
        ac1, ac2, ac3 = st.columns(3)
        avg_close = ent_alerts["time_to_close_min"].mean()
        escalation_rate = ent_alerts["escalated"].mean() * 100
        ac1.metric("Avg Closure Time", f"{avg_close:.0f} min")
        ac2.metric("Escalation Rate", f"{escalation_rate:.1f}%")
        ac3.metric("Total Alerts", len(ent_alerts))

    with tab_alerts:
        st.subheader("Alerts & Cases")
        alert_display = ent_alerts[["alert_id", "severity", "category",
                                     "disposition", "escalated", "time_to_close_min"]].copy()
        alert_display["escalated"] = alert_display["escalated"].map({True: "✓", False: "✗"})

        sev_filter = st.multiselect("Filter by Severity", ["critical", "high", "medium", "low"])
        if sev_filter:
            alert_display = alert_display[alert_display["severity"].isin(sev_filter)]

        st.dataframe(
            alert_display.head(50),
            use_container_width=True,
            hide_index=True,
            column_config={
                "severity": st.column_config.TextColumn("Severity"),
                "time_to_close_min": st.column_config.NumberColumn("Close Time (min)", format="%.0f"),
            },
        )

    with tab_coverage:
        st.subheader("Asset Telemetry Coverage")
        asset_display = ent_assets[["asset_id", "criticality", "asset_type", "telemetry_status"]].copy()
        asset_display["telemetry_status"] = asset_display["telemetry_status"].map({
            "active": "🟢 Active",
            "degraded": "🟡 Degraded",
            "silent": "🔴 Silent",
        })
        st.dataframe(asset_display, use_container_width=True, hide_index=True)

        # Coverage summary
        total_assets = len(ent_assets)
        critical_assets = len(ent_assets[ent_assets["criticality"] == "critical"])
        silent_critical = len(ent_assets[
            (ent_assets["criticality"] == "critical") &
            (ent_assets["telemetry_status"] == "silent")
        ])
        st.warning(
            f"⚠️ {silent_critical} of {critical_assets} critical assets are **silent** "
            f"(no telemetry). Total assets: {total_assets}."
        )

    with tab_findings:
        st.subheader("Entity Findings")
        if ent_findings.empty:
            st.success("✅ No findings for this entity this cycle.")
        else:
            for _, f in ent_findings.iterrows():
                with st.expander(
                    f"{render_type_tag(f['detector_type'])} **{f['finding_id']}** — "
                    f"{f['detector_name']} | Severity: {f['severity'].upper()}"
                    + (" 🔄" if f["recurring"] else ""),
                    expanded=False,
                ):
                    st.markdown(f"**Capability Area:** {f['capability_area']}")
                    st.markdown(f"**Method:** {f['method']}")
                    st.markdown(f"**Confidence:** {f['confidence']:.0%}")
                    st.markdown(f"**Disposition:** {disposition_icon(f['disposition'])} {f['disposition']}")

    with tab_history:
        st.subheader("Historical Trend")
        trend_data = ent_row["trend"]
        fig = go.Figure(go.Scatter(
            y=trend_data,
            x=["Q4-24", "Q1-25", "Q2-25", "Q3-25"],
            mode="lines+markers",
            line=dict(color=risk_color(risk_val), width=3),
        ))
        fig.update_layout(
            height=250,
            yaxis_title="Risk Score",
            margin=dict(t=20),
        )
        st.plotly_chart(fig, use_container_width=True)

    # --- Action Buttons ---
    st.divider()
    b1, b2, b3 = st.columns(3)
    with b1:
        st.button("📊 Compare to Peers", use_container_width=True)
    with b2:
        st.button("📄 Generate Entity Report", use_container_width=True)
    with b3:
        st.button("📋 View Submission Status", use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3: FINDINGS FEED
# ─────────────────────────────────────────────────────────────────────────────

def page_findings():
    """Working list of every supervisory finding."""
    data = st.session_state.data
    findings = data["findings"]

    st.title("🔍 Findings Feed")
    st.caption("All supervisory findings across the portfolio")

    # --- Sidebar Filters ---
    with st.sidebar:
        st.header("🔎 Filters")
        f_entity = st.multiselect("Entity", findings["entity_id"].unique().tolist()[:10])
        f_sector = st.multiselect("Sector", findings["sector"].unique().tolist())
        f_capability = st.multiselect("Capability Area", data["capability_areas"])
        f_severity = st.multiselect("Severity", ["critical", "high", "medium", "low"])
        f_disposition = st.multiselect(
            "Disposition",
            ["pending", "reviewed_benign", "confirmed_escalate", "insufficient_evidence"]
        )

    # Apply filters
    filtered = findings.copy()
    if f_entity:
        filtered = filtered[filtered["entity_id"].isin(f_entity)]
    if f_sector:
        filtered = filtered[filtered["sector"].isin(f_sector)]
    if f_capability:
        filtered = filtered[filtered["capability_area"].isin(f_capability)]
    if f_severity:
        filtered = filtered[filtered["severity"].isin(f_severity)]
    if f_disposition:
        filtered = filtered[filtered["disposition"].isin(f_disposition)]

    # Sort: severity desc, recurring first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    filtered["_sev_order"] = filtered["severity"].map(sev_order)
    filtered["_recur_order"] = filtered["recurring"].map({True: 0, False: 1})
    filtered = filtered.sort_values(["_recur_order", "_sev_order"])

    # --- EG / NS Tabs ---
    tab_eg, tab_ns = st.tabs(["🔴 Execution Gaps (EG)", "🔵 Negative Space (NS)"])

    with tab_eg:
        eg_findings = filtered[filtered["detector_type"] == "EG"]
        if eg_findings.empty:
            st.info("No EG findings match current filters.")
        else:
            for _, f in eg_findings.iterrows():
                recur_badge = " 🔄" if f["recurring"] else ""
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([1, 3, 2, 1])
                    with c1:
                        st.markdown(render_severity_pill(f["severity"]), unsafe_allow_html=True)
                    with c2:
                        st.markdown(
                            f"**{f['finding_id']}** — {f['entity_name']}{recur_badge}\n\n"
                            f"*{f['detector_name']}* | {f['capability_area']}"
                        )
                    with c3:
                        st.caption(f"Confidence: {f['confidence']:.0%} | {f['date_detected']}")
                        st.caption(f"{disposition_icon(f['disposition'])} {f['disposition']}")
                    with c4:
                        if st.button("View", key=f"eg_{f['finding_id']}", use_container_width=True):
                            st.session_state.active_finding_id = f["finding_id"]

    with tab_ns:
        ns_findings = filtered[filtered["detector_type"] == "NS"]
        if ns_findings.empty:
            st.info("No NS findings match current filters.")
        else:
            for _, f in ns_findings.iterrows():
                recur_badge = " 🔄" if f["recurring"] else ""
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([1, 3, 2, 1])
                    with c1:
                        st.markdown(render_severity_pill(f["severity"]), unsafe_allow_html=True)
                    with c2:
                        st.markdown(
                            f"**{f['finding_id']}** — {f['entity_name']}{recur_badge}\n\n"
                            f"*{f['detector_name']}* | {f['capability_area']}"
                        )
                    with c3:
                        st.caption(f"Confidence: {f['confidence']:.0%} | {f['date_detected']}")
                        st.caption(f"{disposition_icon(f['disposition'])} {f['disposition']}")
                    with c4:
                        if st.button("View", key=f"ns_{f['finding_id']}", use_container_width=True):
                            st.session_state.active_finding_id = f["finding_id"]

    # --- Finding Detail (inline) ---
    if st.session_state.active_finding_id:
        st.divider()
        _render_finding_detail(st.session_state.active_finding_id)


def _render_finding_detail(finding_id):
    """Render finding detail as an inline section."""
    data = st.session_state.data
    findings = data["findings"]
    f_row = findings[findings["finding_id"] == finding_id]

    if f_row.empty:
        st.error("Finding not found.")
        return

    f = f_row.iloc[0]

    st.subheader(f"📋 Finding Detail: {f['finding_id']}")

    # Statement
    type_tag = "EG" if f["detector_type"] == "EG" else "NS"
    st.markdown(
        f'<div class="finding-statement">'
        f'{render_type_tag(type_tag)} '
        f'{render_severity_pill(f["severity"])} '
        f' — {f["detector_name"]} flagged for <b>{f["entity_name"]}</b> '
        f'({f["capability_area"]})'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Expanders
    with st.expander("🔬 Why This Fired", expanded=True):
        st.markdown(f"**Detector:** {f['detector_name']}")
        st.markdown(f"**Method:** {f['method']}")
        st.markdown(f"**Observed Value:** {f['observed_value']}")
        st.markdown(f"**Baseline:** {f['baseline_value']}")
        st.markdown(f"**Threshold:** {f['threshold']}")
        st.code(
            f"Statistic: observed={f['observed_value']} vs threshold={f['threshold']}\n"
            f"Baseline reference: {f['baseline_value']}\n"
            f"Rule: {f['method']}",
            language=None,
        )

    with st.expander("📎 Evidence"):
        st.markdown(f"**Alert/Asset IDs:** AL-{f['finding_id'][-5:]}")
        st.markdown(f"**Entity:** {f['entity_id']} ({f['entity_name']})")
        st.markdown(f"**Detection Date:** {f['date_detected']}")
        st.markdown(f"**Confidence:** {f['confidence']:.0%}")

    with st.expander("📊 Peer Context"):
        # Simulated peer distribution
        peer_values = np.random.normal(f["baseline_value"], 50, 30)
        fig = go.Figure()
        fig.add_trace(go.Box(y=peer_values, name="Peer Distribution", boxpoints=False))
        fig.add_trace(go.Scatter(
            y=[f["observed_value"]], x=["This Entity"],
            mode="markers", marker=dict(size=12, color="#ff4b4b"),
            name="Entity Value",
        ))
        fig.update_layout(height=250, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("📅 History"):
        if f["recurring"]:
            st.warning("🔄 This detector fired for this entity in the **prior cycle** as well.")
        else:
            st.success("This is the first occurrence for this entity.")

    # --- Disposition Control ---
    st.divider()
    st.subheader("⚖️ Disposition")

    d1, d2 = st.columns([2, 1])
    with d1:
        disp_choice = st.radio(
            "Disposition",
            ["Reviewed – Benign", "Confirmed – Escalate", "Insufficient Evidence"],
            horizontal=True,
            key=f"disp_{finding_id}",
        )
        note = st.text_area("Examiner Note", key=f"note_{finding_id}")
    with d2:
        st.write("")
        st.write("")
        if st.button("💾 Save Disposition", type="primary", key=f"save_{finding_id}"):
            st.session_state.dispositions[finding_id] = {
                "disposition": disp_choice,
                "note": note,
                "examiner": "Examiner A",
                "timestamp": datetime.now().isoformat(),
            }
            st.success(f"✅ Disposition saved for {finding_id}")
            st.balloons()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 4: PEER BENCHMARKING
# ─────────────────────────────────────────────────────────────────────────────

def page_benchmarking():
    """Peer benchmarking with distribution plots."""
    data = st.session_state.data
    scores = data["scores"]

    st.title("📊 Peer Benchmarking")
    st.caption("Compare entity metrics against sector peer distributions")

    # Controls
    c1, c2, c3 = st.columns(3)
    with c1:
        selected_sector = st.selectbox("Sector", scores["sector"].unique().tolist())
    with c2:
        metric = st.selectbox(
            "Metric",
            ["risk_score", "eg_count", "ns_count", "alert_volume"]
        )
    with c3:
        selected_entity = st.selectbox(
            "Highlight Entity",
            scores[scores["sector"] == selected_sector]["entity_id"].tolist(),
        )

    sector_data = scores[scores["sector"] == selected_sector]

    # Box/Violin plot
    fig = go.Figure()

    # Distribution
    fig.add_trace(go.Violin(
        y=sector_data[metric],
        name="Sector Distribution",
        box_visible=True,
        meanline_visible=True,
        fillcolor="#1c83e133",
        line_color="#1c83e1",
        points="all",
        jitter=0.3,
        pointpos=-1.5,
    ))

    # Highlight selected entity
    ent_val = sector_data[sector_data["entity_id"] == selected_entity][metric].values
    if len(ent_val) > 0:
        fig.add_trace(go.Scatter(
            y=ent_val,
            x=[selected_entity],
            mode="markers",
            marker=dict(size=16, color="#ff4b4b", symbol="diamond"),
            name=f"{selected_entity}",
        ))

    fig.update_layout(
        height=400,
        title=f"{metric.replace('_', ' ').title()} — {selected_sector}",
        yaxis_title=metric.replace("_", " ").title(),
        showlegend=True,
    )
    st.plotly_chart(fig, use_container_width=True)

    # Ranked table
    st.subheader("Sector Ranking")
    ranked = sector_data.sort_values(metric, ascending=False)[
        ["entity_id", "name", metric, "risk_score"]
    ].reset_index(drop=True)
    ranked.index += 1
    ranked.columns = ["Rank", "Entity ID", "Name", "Metric Value", "Risk Score"]

    st.dataframe(
        ranked,
        use_container_width=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                min_value=0, max_value=5, format="%.2f"
            ),
        },
    )

    # Percentile
    ent_metric = sector_data[sector_data["entity_id"] == selected_entity][metric].values
    if len(ent_metric) > 0:
        percentile = (sector_data[metric] < ent_metric[0]).mean() * 100
        st.info(f"📍 **{selected_entity}** is at the **{percentile:.0f}th percentile** for {metric} in {selected_sector}.")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 5: REVIEW QUEUE
# ─────────────────────────────────────────────────────────────────────────────

def page_review_queue():
    """Examiner's personal prioritized to-do list."""
    data = st.session_state.data
    queue = data["queue"]

    st.title("📋 Review Queue")
    st.caption("Prioritized items requiring examiner attention")

    if queue.empty:
        st.success("✅ Queue is clear. No pending items.")
        return

    # Summary metrics
    qm1, qm2, qm3 = st.columns(3)
    qm1.metric("Total Items", len(queue))
    qm2.metric("To Review", len(queue[queue["status"] == "To review"]))
    qm3.metric("In Progress", len(queue[queue["status"] == "In progress"]))

    st.divider()

    # Queue items
    for idx, item in queue.iterrows():
        status_key = f"status_{item['item_id']}"
        current_status = st.session_state.queue_updates.get(
            item["item_id"], item["status"]
        )

        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([1, 4, 2, 2])
            with c1:
                st.markdown(f"**{item['priority_score']:.1f}**")
            with c2:
                st.markdown(f"**{item['item_id']}** — {item['entity_name']}")
                st.caption(item["reason"])
            with c3:
                new_status = st.selectbox(
                    "Status",
                    ["To review", "In progress", "Done"],
                    index=["To review", "In progress", "Done"].index(current_status),
                    key=status_key,
                    label_visibility="collapsed",
                )
                if new_status != current_status:
                    st.session_state.queue_updates[item["item_id"]] = new_status
            with c4:
                assignee = st.text_input(
                    "Assignee",
                    value=item.get("assignee", ""),
                    key=f"assign_{item['item_id']}",
                    label_visibility="collapsed",
                    placeholder="Assign to...",
                )

    # Filter by status
    st.divider()
    status_filter = st.radio(
        "Filter",
        ["All", "To review", "In progress", "Done"],
        horizontal=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 6: DATA HEALTH
# ─────────────────────────────────────────────────────────────────────────────

def page_data_health():
    """Data health / submissions matrix."""
    data = st.session_state.data
    submissions = data["submissions"]
    categories = data["categories"]

    st.title("📡 Data Health / Submissions")
    st.caption(
        "Separating **'didn't submit'** (compliance problem) from "
        "**'submitted but sparse'** (negative-space candidate)"
    )

    # Build matrix
    pivot = submissions.pivot_table(
        index=["entity_id", "name"],
        columns="category",
        values="status",
        aggfunc="first",
    ).reset_index()

    # Color mapping
    color_map = {
        "submitted": "🟢",
        "sparse": "🟡",
        "not_submitted": "🔴",
    }

    display_pivot = pivot.copy()
    for cat in categories:
        if cat in display_pivot.columns:
            display_pivot[cat] = display_pivot[cat].map(color_map).fillna("⬜")

    st.dataframe(
        display_pivot,
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # Legend
    st.markdown("**Legend:** 🟢 Submitted & Complete | 🟡 Submitted & Sparse | 🔴 Not Submitted")

    # Quarantine info
    st.subheader("🚫 Ingestion Quality (Quarantine)")
    st.caption("Records that failed CDM/Pydantic validation on ingestion")

    quarantine_data = pd.DataFrame({
        "Entity": [f"CSE-{i:03d}" for i in range(1, 8)],
        "Quarantined Records": np.random.randint(0, 50, 7),
        "Total Submitted": np.random.randint(200, 1000, 7),
    })
    quarantine_data["Reject Rate %"] = (
        quarantine_data["Quarantined Records"] / quarantine_data["Total Submitted"] * 100
    ).round(1)

    st.dataframe(quarantine_data, use_container_width=True, hide_index=True)

    # Alert for high quarantine
    high_quarantine = quarantine_data[quarantine_data["Reject Rate %"] > 3]
    if not high_quarantine.empty:
        st.warning(
            f"⚠️ {len(high_quarantine)} entities have quarantine rates above 3%. "
            "This may indicate schema drift or data quality issues worth investigating."
        )

    # Link to NS findings
    st.divider()
    sparse_entities = submissions[submissions["status"] == "sparse"]["entity_id"].unique()
    st.info(
        f"💡 **{len(sparse_entities)} entities** have sparse submissions. "
        "These are negative-space candidates (submitted but insufficient data)."
    )
    if st.button("→ View NS Findings for Sparse Entities"):
        st.session_state.nav_history.append("Findings")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 7: DETECTOR LIBRARY
# ─────────────────────────────────────────────────────────────────────────────

def page_detector_library():
    """Detector/rule library for audit and transparency."""
    data = st.session_state.data
    detectors = data["detectors"]

    st.title("📚 Detector Library")
    st.caption("Explainability and auditability of the rule set")

    st.dataframe(
        detectors,
        use_container_width=True,
        hide_index=True,
        column_config={
            "rule_id": st.column_config.TextColumn("Rule ID", width="small"),
            "description": st.column_config.TextColumn("Description", width="large"),
            "method": st.column_config.TextColumn("Method", width="medium"),
            "threshold": st.column_config.TextColumn("Threshold", width="medium"),
            "capability_area": st.column_config.TextColumn("Capability", width="small"),
            "type": st.column_config.TextColumn("Type", width="small"),
            "last_calibrated": st.column_config.DateColumn("Last Calibrated"),
            "fired_this_cycle": st.column_config.NumberColumn("Fired This Cycle"),
        },
    )

    st.divider()

    # Detail view per detector
    for _, det in detectors.iterrows():
        with st.expander(f"**{det['rule_id']}** — {det['description'][:80]}...", expanded=False):
            d1, d2 = st.columns(2)
            with d1:
                st.markdown(f"**Method:** {det['method']}")
                st.markdown(f"**Threshold:** `{det['threshold']}`")
                st.markdown(f"**Capability Area:** {det['capability_area']}")
            with d2:
                st.markdown(f"**Type:** {det['type']}")
                st.markdown(f"**Last Calibrated:** {det['last_calibrated']}")
                st.markdown(f"**Fired This Cycle:** {det['fired_this_cycle']}")

            if det["type"] == "EG":
                st.markdown(
                    "> **Execution Gap:** Detects cases where expected security processes "
                    "were not followed (e.g., alerts closed too fast, no escalation)."
                )
            else:
                st.markdown(
                    "> **Negative Space:** Detects the *absence* of expected activity "
                    "(e.g., critical assets with unusually low alert volume vs peers)."
                )

            if st.button(f"View findings for {det['rule_id']}", key=f"det_{det['rule_id']}"):
                st.session_state.nav_history.append("Findings")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 8: REPORT CENTER
# ─────────────────────────────────────────────────────────────────────────────

def page_reports():
    """Report generation and export."""
    data = st.session_state.data
    scores = data["scores"]
    findings = data["findings"]

    st.title("📄 Report Center")
    st.caption("Generate reports from reviewed data — nothing appears here that wasn't visible in the UI")

    # Controls
    c1, c2, c3 = st.columns(3)
    with c1:
        report_scope = st.radio(
            "Scope",
            ["Portfolio-wide", "Single Entity"],
            horizontal=True,
        )
    with c2:
        if report_scope == "Single Entity":
            entity_sel = st.selectbox("Entity", scores["entity_id"].tolist())
        else:
            entity_sel = None
    with c3:
        report_type = st.selectbox(
            "Report Type",
            ["Entity Assessment", "Portfolio Summary", "Findings Export (CSV)"],
        )

    st.divider()

    # Preview
    st.subheader("📋 Report Preview")

    if report_type == "Portfolio Summary":
        st.markdown(f"### Portfolio Summary — {st.session_state.active_cycle}")
        st.markdown(f"- **Entities Assessed:** {len(scores)}")
        st.markdown(f"- **Total Findings:** {len(findings)}")
        st.markdown(f"- **EG Findings:** {len(findings[findings['detector_type']=='EG'])}")
        st.markdown(f"- **NS Findings:** {len(findings[findings['detector_type']=='NS'])}")
        st.markdown(f"- **Average Risk Score:** {scores['risk_score'].mean():.2f}")
        st.markdown(f"- **Entities with No Submission:** {len(scores[scores['submission_status']=='not_submitted'])}")

        # Top 5 risk
        st.markdown("#### Top 5 Entities by Risk")
        top5 = scores.nlargest(5, "risk_score")[["entity_id", "name", "risk_score"]]
        st.dataframe(top5, use_container_width=True, hide_index=True)

    elif report_type == "Entity Assessment" and entity_sel:
        ent = scores[scores["entity_id"] == entity_sel].iloc[0]
        ent_findings = findings[findings["entity_id"] == entity_sel]
        st.markdown(f"### Entity Assessment: {ent['name']} ({entity_sel})")
        st.markdown(f"- **Sector:** {ent['sector']}")
        st.markdown(f"- **Risk Score:** {ent['risk_score']:.2f}")
        st.markdown(f"- **Priority Rank:** #{ent['priority_rank']}")
        st.markdown(f"- **Total Findings:** {len(ent_findings)}")

    elif report_type == "Findings Export (CSV)":
        export_df = findings[["finding_id", "entity_id", "detector_name",
                              "severity", "capability_area", "disposition"]].copy()
        st.dataframe(export_df.head(20), use_container_width=True, hide_index=True)
        st.caption(f"Showing {min(20, len(export_df))} of {len(export_df)} findings")

    # Download
    st.divider()
    st.subheader("💾 Export")

    if report_type == "Findings Export (CSV)":
        csv_data = findings.to_csv(index=False)
        st.download_button(
            "📥 Download Findings CSV",
            data=csv_data,
            file_name=f"satsa_findings_{st.session_state.active_cycle}.csv",
            mime="text/csv",
            type="primary",
        )
    else:
        # Simulate PDF generation
        report_json = {
            "generated_at": datetime.now().isoformat(),
            "cycle": st.session_state.active_cycle,
            "report_type": report_type,
            "entity": entity_sel,
            "summary": {
                "total_entities": len(scores),
                "total_findings": len(findings),
            },
        }
        st.download_button(
            "📥 Download Report (JSON)",
            data=json.dumps(report_json, indent=2),
            file_name=f"satsa_report_{st.session_state.active_cycle}.json",
            mime="application/json",
            type="primary",
        )


# ─────────────────────────────────────────────────────────────────────────────
# NAVIGATION SETUP
# ─────────────────────────────────────────────────────────────────────────────

# Define pages
portfolio_page = st.Page(page_portfolio, title="Portfolio", icon="🏠", default=True)
entity_page = st.Page(page_entity_profile, title="Entity Profile", icon="🏢")
findings_page = st.Page(page_findings, title="Findings", icon="🔍")
benchmark_page = st.Page(page_benchmarking, title="Peer Benchmarking", icon="📊")
queue_page = st.Page(page_review_queue, title="Review Queue", icon="📋")
health_page = st.Page(page_data_health, title="Data Health", icon="📡")
detector_page = st.Page(page_detector_library, title="Detector Library", icon="📚")
reports_page = st.Page(page_reports, title="Reports", icon="📄")

# Navigation
pg = st.navigation({
    "Assessment": [portfolio_page, entity_page, findings_page],
    "Analysis": [benchmark_page, queue_page, health_page],
    "Audit & Output": [detector_page, reports_page],
})

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL SIDEBAR ELEMENTS
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ SAT-SA")
    st.caption("Supervisory Analytics Tool for SOC Assessment")
    st.divider()

    # Cycle selector
    cycle = st.selectbox(
        "📅 Assessment Cycle",
        ["2025-Q3", "2025-Q2", "2025-Q1", "2024-Q4"],
        index=0,
    )
    st.session_state.active_cycle = cycle

    st.divider()

    # Global search
    search = st.text_input("🔎 Search (Entity / Finding ID)", placeholder="CSE-001 or FG-00001")
    if search:
        data = st.session_state.data
        # Search entities
        ent_match = data["scores"][
            data["scores"]["entity_id"].str.contains(search, case=False) |
            data["scores"]["name"].str.contains(search, case=False)
        ]
        if not ent_match.empty:
            st.success(f"Found {len(ent_match)} entities")
            for _, e in ent_match.head(3).iterrows():
                if st.button(f"{e['entity_id']}: {e['name']}", key=f"search_{e['entity_id']}"):
                    st.session_state.active_entity_id = e["entity_id"]

        # Search findings
        find_match = data["findings"][
            data["findings"]["finding_id"].str.contains(search, case=False)
        ]
        if not find_match.empty:
            st.success(f"Found {len(find_match)} findings")
            for _, f in find_match.head(3).iterrows():
                if st.button(f"{f['finding_id']}: {f['detector_name']}", key=f"search_{f['finding_id']}"):
                    st.session_state.active_finding_id = f["finding_id"]

    st.divider()

    # Breadcrumb
    st.caption("**Navigation:**")
    st.caption(" → ".join(st.session_state.nav_history[-3:]))

    st.divider()

    # Footer
    st.caption("---")
    st.caption("👤 **Examiner:** NCIIPC Supervisor")
    st.caption(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    st.caption("🔒 Offline / Air-gapped")


# ─────────────────────────────────────────────────────────────────────────────
# RUN THE SELECTED PAGE
# ─────────────────────────────────────────────────────────────────────────────
pg.run()
