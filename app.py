from __future__ import annotations

from pathlib import Path

import streamlit as st

from core.auth import logout, require_login
from core.css import load_css
from core.sidebar import render_sidebar


st.set_page_config(
    page_title="Cyber Threat Research",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

load_css()

if not require_login():
    st.stop()

render_sidebar()

with st.sidebar:
    st.markdown("---")

    st.markdown(
        f"""
        <div class="logged-user">
            <small>Usuário conectado</small>
            <strong>
                👤 {st.session_state.get("username", "usuário")}
            </strong>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("Sair da conta", use_container_width=True):
        logout()


st.markdown(
    """
    <section class="hero-home">
        <div class="hero-badge">⚡ CTR DEFENSE PLATFORM</div>
        <h1>Cyber Threat Research</h1>
        <p>
            Investigue indicadores de comprometimento, reputação,
            vazamentos e inteligência de ameaças em um único ambiente.
        </p>
    </section>
    """,
    unsafe_allow_html=True,
)

st.markdown("### Visão geral")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Módulos ativos", "4")

with col2:
    st.metric("Consultas realizadas", "—")

with col3:
    st.metric("Indicadores analisados", "—")

with col4:
    st.metric("Status da plataforma", "Online")


tools = [
    (
        "🔎",
        "Extrator de IOCs",
        "Extraia IPs, domínios, hashes e URLs de textos e arquivos.",
        "1_Extrator_IOCs.py",
    ),
    (
        "🛡️",
        "AbuseIPDB",
        "Consulte reputação, score de abuso e relatórios de IPs.",
        "2_AbuseIPDB.py",
    ),
    (
        "🧪",
        "VirusTotal",
        "Analise IPs, domínios, URLs e hashes.",
        "3_VirusTotal.py",
    ),
    (
        "🧠",
        "Threat Intelligence",
        "Organize e correlacione informações de investigação.",
        "4_Threat_Intelligence.py",
    ),
    (
        "📊",
        "Relatórios",
        "Consulte o histórico das análises realizadas.",
        "5_Relatorios.py",
    ),
    (
        "📧",
        "Vazamento de E-mail",
        "Verifique a presença de e-mails em vazamentos públicos.",
        "6_Vazamento_Email.py",
    ),
]

pages_path = Path(__file__).parent / "pages"

existing_tools = [
    tool for tool in tools
    if (pages_path / tool[3]).exists()
]

st.markdown("### Ferramentas disponíveis")

for start in range(0, len(existing_tools), 3):
    row = existing_tools[start:start + 3]
    columns = st.columns(3)

    for column, tool in zip(columns, row):
        icon, title, description, _filename = tool

        with column:
            st.markdown(
                f"""
                <div class="home-tool-card">
                    <div class="home-tool-icon">{icon}</div>
                    <h3>{title}</h3>
                    <p>{description}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

st.markdown(
    """
    <div class="home-notice">
        <strong>🔐 Segurança</strong>
        <span>
            As credenciais devem ficar em secrets.toml e nunca no
            código-fonte.
        </span>
    </div>

    <footer class="home-footer">
        © 2024–2026 Cyber Threat Research · Uso autorizado e responsável
    </footer>
    """,
    unsafe_allow_html=True,
)
