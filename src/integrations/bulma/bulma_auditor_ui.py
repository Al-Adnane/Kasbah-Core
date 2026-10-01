"""
BULMA AUDITOR - Streamlit Frontend
User-Friendly Dashboard for Defensibility Analysis

Run with: streamlit run bulma_auditor_ui.py
"""

import streamlit as st
import requests
import json
from datetime import datetime
from typing import Optional
import pandas as pd
import plotly.graph_objects as go

# Page config
st.set_page_config(
    page_title="Bulma Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .score-high {
        color: #00AA00;
        font-weight: bold;
        font-size: 28px;
    }
    .score-medium {
        color: #FF9500;
        font-weight: bold;
        font-size: 28px;
    }
    .score-low {
        color: #FF0000;
        font-weight: bold;
        font-size: 28px;
    }
    .vulnerability-critical {
        background-color: #ffe6e6;
        border-left: 4px solid #ff0000;
        padding: 10px;
        margin: 5px 0;
    }
    .vulnerability-high {
        background-color: #fff3e0;
        border-left: 4px solid #ff9500;
        padding: 10px;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)

# API Base URL (configurable)
API_BASE_URL = st.secrets.get("API_URL", "http://localhost:8000")

# ─────────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("# 🛡️ Bulma Auditor")
st.markdown("### Multi-Archetype Reasoning Auditor for Truth-Seeking AI")

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Configuration")

    mode = st.radio(
        "Select Mode",
        ["New Audit", "View History", "About"]
    )

    if mode == "About":
        st.info("""
        **Bulma Auditor** is a production-ready defensibility engine that validates
        claims using six complementary reasoning strategies:

        - 🧠 **L Deduction** - Contradiction detection
        - 📋 **Light Planning** - Scenario modeling
        - ⚡ **Shikamaru Efficiency** - Complexity optimization
        - 🔍 **Lelouch Detection** - Bias detection
        - 🔄 **Tanya Adaptation** - Uncertainty handling
        - 🎓 **Frieren Wisdom** - Pattern matching

        **Use Cases**: Legal review, AI validation, research verification,
        contract analysis, executive decision support.
        """)

        st.divider()

        st.subheader("Version & Status")
        st.text("""
        Version: 1.0.0 (MVP)
        Status: Production Ready
        Backend: FastAPI + Python
        Frontend: Streamlit
        """)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN CONTENT
# ─────────────────────────────────────────────────────────────────────────────

if mode == "New Audit":
    st.header("New Audit")

    # Input section
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📝 Claims")
        claims_text = st.text_area(
            "Enter claims (one per line)",
            value="The capital of France is Paris.\nParis is located in Western Europe.",
            height=150,
            help="Each line is treated as a separate claim to evaluate"
        )

    with col2:
        st.subheader("📚 Evidence Sources")
        evidence_text = st.text_area(
            "Enter evidence sources (one per line)",
            value="Wikipedia\nEncyclopedia Britannica",
            height=150,
            help="References that support your claims"
        )

    st.subheader("📖 Narrative Context (Optional)")
    narrative = st.text_input(
        "Provide context or background",
        value="Basic geographic facts",
        help="Helps the auditor understand the domain"
    )

    # Options
    col1, col2 = st.columns(2)
    with col1:
        include_trace = st.checkbox("Include Reasoning Trace", value=True)
    with col2:
        auto_export = st.checkbox("Auto-Export Results", value=False)

    # Parse inputs
    claims = [c.strip() for c in claims_text.split("\n") if c.strip()]
    evidence = [e.strip() for e in evidence_text.split("\n") if e.strip()]

    # Run audit button
    if st.button("🚀 Run Audit", type="primary", use_container_width=True):
        with st.spinner("Analyzing claims with 6 reasoning strategies..."):
            try:
                # Call API
                response = requests.post(
                    f"{API_BASE_URL}/api/v1/audit",
                    json={
                        "claims": claims,
                        "evidence_sources": evidence,
                        "narrative_context": narrative,
                        "include_trace": include_trace
                    },
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()

                    # Store in session for display
                    st.session_state.audit_result = result

                    st.success("✅ Audit Complete!")

                else:
                    st.error(f"API Error: {response.status_code}")
                    st.text(response.text)

            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot connect to API server. Make sure it's running on localhost:8000")
            except Exception as e:
                st.error(f"Error: {str(e)}")

    # Display results if available
    if "audit_result" in st.session_state:
        result = st.session_state.audit_result

        st.divider()
        st.header("📊 Results")

        # Score display
        score = result['defensibility_score']
        confidence = result['confidence_level']

        col1, col2, col3 = st.columns(3)

        with col1:
            if score >= 85:
                st.metric(
                    "Defensibility Score",
                    f"{score}%",
                    delta="Excellent",
                    delta_color="off"
                )
            elif score >= 70:
                st.metric(
                    "Defensibility Score",
                    f"{score}%",
                    delta="Good",
                    delta_color="off"
                )
            else:
                st.metric(
                    "Defensibility Score",
                    f"{score}%",
                    delta="Needs Work",
                    delta_color="inverse"
                )

        with col2:
            st.metric("Confidence Level", confidence)

        with col3:
            st.metric("Audit ID", result['audit_id'][:12])

        # Archetype scores radar chart
        st.subheader("🎯 Strategy Analysis")

        archetypes = [a['archetype'].upper() for a in result['archetype_scores']]
        scores = [a['score'] * 100 for a in result['archetype_scores']]

        fig = go.Figure(data=go.Scatterpolar(
            r=scores,
            theta=archetypes,
            fill='toself',
            name='Defensibility Score'
        ))

        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            showlegend=False,
            height=400
        )

        st.plotly_chart(fig, use_container_width=True)

        # Archetype details
        st.subheader("Strategy Breakdown")

        for archetype in result['archetype_scores']:
            with st.expander(f"**{archetype['archetype'].title()}** - {archetype['score']:.1%}"):
                st.write(archetype['reasoning'])
                st.write("**Key Findings:**")
                for finding in archetype['key_findings']:
                    st.write(f"- {finding}")
                st.write(f"Weight: {archetype['weight']:.1%} | Contribution: {archetype['weighted_contribution']:.3f}")

        # Vulnerabilities
        if result['vulnerabilities']:
            st.subheader("⚠️ Vulnerabilities")

            for vuln in result['vulnerabilities']:
                severity_color = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                    "info": "ℹ️"
                }

                with st.expander(
                    f"{severity_color.get(vuln['severity'], '❓')} "
                    f"**{vuln['type'].upper()}** (Confidence: {vuln['confidence']:.0%})"
                ):
                    st.write(vuln['description'])
                    st.write(f"**Affected Claims:** {vuln['affected_claims']}")
                    st.write(f"**Remediation:** {vuln['remediation']}")

        else:
            st.success("✅ No major vulnerabilities detected")

        # Recommendations
        st.subheader("💡 Recommendations")

        st.info(result['primary_recommendation'])

        st.write("**Action Items:**")
        for i, item in enumerate(result['action_items'], 1):
            st.write(f"{i}. {item}")

        # Export options
        st.divider()
        st.subheader("📥 Export Results")

        col1, col2, col3 = st.columns(3)

        with col1:
            json_str = json.dumps(result, indent=2, default=str)
            st.download_button(
                "📄 JSON",
                json_str,
                file_name=f"audit_{result['audit_id']}.json",
                mime="application/json"
            )

        with col2:
            # Simple markdown export
            markdown = f"""
# Bulma Auditor Report
**Audit ID:** {result['audit_id']}
**Timestamp:** {result['timestamp']}

## Score
**Defensibility:** {result['defensibility_score']}%
**Confidence:** {result['confidence_level']}

## Recommendation
{result['primary_recommendation']}

## Vulnerabilities
Total: {len(result['vulnerabilities'])}

## Archetypes
"""
            for a in result['archetype_scores']:
                markdown += f"\n- {a['archetype'].upper()}: {a['score']:.1%}"

            st.download_button(
                "📑 Markdown",
                markdown,
                file_name=f"audit_{result['audit_id']}.md",
                mime="text/markdown"
            )

        with col3:
            # CSV export for archetype scores
            df = pd.DataFrame({
                'Archetype': [a['archetype'] for a in result['archetype_scores']],
                'Score': [a['score'] for a in result['archetype_scores']],
                'Weight': [a['weight'] for a in result['archetype_scores']],
                'Contribution': [a['weighted_contribution'] for a in result['archetype_scores']]
            })

            csv = df.to_csv(index=False)
            st.download_button(
                "📊 CSV",
                csv,
                file_name=f"audit_{result['audit_id']}_breakdown.csv",
                mime="text/csv"
            )

        # Reasoning trace (if available)
        if include_trace and result['reasoning_trace']:
            with st.expander("🔍 Full Reasoning Trace"):
                st.json(result['reasoning_trace'])


elif mode == "View History":
    st.header("📜 Audit History")

    try:
        response = requests.get(f"{API_BASE_URL}/api/v1/audits?limit=50")

        if response.status_code == 200:
            data = response.json()

            if data['audits']:
                # Convert to dataframe for nice display
                df = pd.DataFrame(data['audits'])

                st.dataframe(
                    df,
                    use_container_width=True,
                    hide_index=True
                )

                # Allow retrieving specific audit
                st.divider()
                st.subheader("Retrieve Specific Audit")

                audit_id = st.text_input("Enter Audit ID")

                if audit_id:
                    response = requests.get(f"{API_BASE_URL}/api/v1/audit/{audit_id}")
                    if response.status_code == 200:
                        audit = response.json()
                        st.json(audit)
                    else:
                        st.error("Audit not found")

            else:
                st.info("No audits yet. Create one to get started!")

        else:
            st.error("Failed to fetch history")

    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to API server")


# Footer
st.divider()
st.markdown("""
<div style="text-align: center; color: gray; font-size: 12px;">
    Bulma Auditor v1.0 • Multi-Archetype Defensibility Engine<br>
    Built with ❤️ for Truth-Seeking AI
</div>
""", unsafe_allow_html=True)
