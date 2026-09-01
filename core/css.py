# core/css.py

from __future__ import annotations

import streamlit as st


def apply_cyberpunk_css() -> None:
    """
    Aplica o tema visual do Cyber Threat Research.
    """

    st.markdown(
        """
        <style>

        /* =========================================================
           CONFIGURAÇÕES GERAIS
        ========================================================= */

        :root {
            --bg-main: #070b14;
            --bg-panel: #101827;
            --bg-panel-hover: #172337;
            --bg-sidebar: #20232d;
            --border: #263852;
            --border-hover: #08d9ff;
            --text: #edf4ff;
            --text-muted: #92a4bd;
            --cyan: #00d9ff;
            --cyan-dark: #008eac;
            --green: #48e89a;
            --orange: #ffad42;
            --danger: #ff5f73;
            --shadow: 0 8px 26px rgba(0, 0, 0, 0.28);
        }

        /* Remove o espaço superior exagerado do Streamlit */
        .block-container {
            max-width: 1450px !important;
            padding-top: 2.5rem !important;
            padding-bottom: 3rem !important;
            padding-left: 3rem !important;
            padding-right: 3rem !important;
        }

        .stApp {
            background:
                radial-gradient(
                    circle at 50% 0%,
                    rgba(0, 174, 255, 0.08),
                    transparent 38%
                ),
                var(--bg-main);
            color: var(--text);
        }

        /* =========================================================
           BARRA LATERAL
        ========================================================= */

        section[data-testid="stSidebar"] {
            background: var(--bg-sidebar);
            border-right: 1px solid #303746;
        }

        section[data-testid="stSidebar"] > div {
            padding: 1rem 0.75rem;
        }

        section[data-testid="stSidebar"] .block-container {
            padding: 0 !important;
        }

        section[data-testid="stSidebar"] hr {
            border-color: #464b58;
            margin: 1.25rem 0;
        }

        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] p {
            color: var(--text);
        }

        section[data-testid="stSidebar"] .stTextInput input,
        section[data-testid="stSidebar"] .stSelectbox div[data-baseweb="select"] {
            background: #0e1420;
            border: 1px solid #303b52;
            border-radius: 8px;
        }

        /* =========================================================
           TÍTULOS
        ========================================================= */

        h1,
        h2,
        h3 {
            color: var(--text) !important;
            letter-spacing: -0.02em;
        }

        h1 {
            font-size: clamp(2rem, 4vw, 3.2rem) !important;
            font-weight: 800 !important;
        }

        h2 {
            margin-top: 2rem !important;
            margin-bottom: 1rem !important;
            font-size: 1.65rem !important;
        }

        h3 {
            font-size: 1.1rem !important;
        }

        /* =========================================================
           CABEÇALHO
        ========================================================= */

        .ctr-header {
            text-align: center;
            padding: 0.5rem 0 2.5rem;
        }

        .ctr-header h1 {
            color: var(--cyan) !important;
            text-shadow: 0 0 18px rgba(0, 217, 255, 0.38);
            margin-bottom: 0.35rem !important;
        }

        .ctr-header p {
            color: #9bb3d2;
            font-size: 1.05rem;
            margin: 0;
        }

        /* =========================================================
           STATUS DOS SERVIÇOS
        ========================================================= */

        .status-card {
            background: linear-gradient(
                145deg,
                #111c2d,
                #0c1421
            );
            border: 1px solid var(--border);
            border-radius: 12px;
            min-height: 108px;
            padding: 1rem;
            text-align: center;
            box-shadow: var(--shadow);
            transition: 0.2s ease;
        }

        .status-card:hover {
            border-color: var(--border-hover);
            transform: translateY(-2px);
        }

        .status-name {
            color: #cbd9ec;
            font-size: 0.9rem;
            font-weight: 600;
            margin-bottom: 0.7rem;
        }

        .status-indicator {
            width: 18px;
            height: 18px;
            margin: 0 auto;
            border-radius: 50%;
            background: var(--green);
            box-shadow:
                0 0 0 5px rgba(72, 232, 154, 0.12),
                0 0 18px rgba(72, 232, 154, 0.9);
        }

        .status-indicator.offline {
            background: var(--danger);
            box-shadow:
                0 0 0 5px rgba(255, 95, 115, 0.12),
                0 0 18px rgba(255, 95, 115, 0.8);
        }

        /* =========================================================
           CARDS DE FERRAMENTAS
        ========================================================= */

        .tool-card {
            display: block;
            height: 100%;
            min-height: 155px;
            padding: 1.25rem;
            background: linear-gradient(
                145deg,
                var(--bg-panel),
                #0c1320
            );
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: var(--shadow);
            transition:
                transform 0.2s ease,
                border-color 0.2s ease,
                background 0.2s ease;
        }

        .tool-card:hover {
            transform: translateY(-4px);
            background: var(--bg-panel-hover);
            border-color: var(--border-hover);
        }

        .tool-icon {
            font-size: 1.8rem;
            margin-bottom: 0.55rem;
        }

        .tool-title {
            color: var(--cyan);
            font-size: 1.1rem;
            font-weight: 750;
            margin-bottom: 0.55rem;
        }

        .tool-description {
            color: var(--text-muted);
            font-size: 0.9rem;
            line-height: 1.5;
        }

        /* Remove sublinhado e aparência de link dos cards */
        .tool-card,
        .tool-card:hover,
        .tool-card:visited {
            text-decoration: none !important;
        }

        /* =========================================================
           INPUTS E BOTÕES
        ========================================================= */

        .stTextInput input,
        .stTextArea textarea {
            background: #111a2a !important;
            color: var(--text) !important;
            border: 1px solid #2d3c57 !important;
            border-radius: 9px !important;
        }

        .stTextInput input:focus,
        .stTextArea textarea:focus {
            border-color: var(--cyan) !important;
            box-shadow: 0 0 0 1px var(--cyan) !important;
        }

        .stButton > button {
            border: 1px solid #285171;
            border-radius: 8px;
            background: linear-gradient(
                135deg,
                #10243b,
                #12314a
            );
            color: #eaf8ff;
            font-weight: 650;
            transition: 0.2s ease;
        }

        .stButton > button:hover {
            border-color: var(--cyan);
            color: var(--cyan);
            box-shadow: 0 0 15px rgba(0, 217, 255, 0.2);
        }

        /* =========================================================
           RODAPÉ
        ========================================================= */

        .ctr-footer {
            margin-top: 3.5rem;
            padding-top: 1.2rem;
            border-top: 1px solid #233148;
            text-align: center;
            color: #7188a7;
            font-size: 0.82rem;
        }

        /* =========================================================
           RESPONSIVIDADE
        ========================================================= */

        @media (max-width: 900px) {
            .block-container {
                padding-left: 1.25rem !important;
                padding-right: 1.25rem !important;
            }

            .tool-card {
                min-height: auto;
            }
        }

        </style>
        """,
        unsafe_allow_html=True,
    )
