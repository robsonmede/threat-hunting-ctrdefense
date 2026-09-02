from __future__ import annotations

from pathlib import Path

import streamlit as st

from core.auth import logout, require_login
from core.css import load_css
from core.sidebar import render_sidebar

from ui_sidebar import aplicar_sidebar



st.set_page_config(
    page_title="Cyber Threat Research 3.9",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

aplicar_sidebar()



# >>> NAVEGACAO_HOME_FRONTEND >>>
def _renderizar_link_home_sidebar():
    """
    Mantém o arquivo app.py e altera somente sua apresentação
    na navegação lateral do Streamlit.
    """

    st.markdown(
        """
        <style>
        /*
         * Oculta somente o primeiro item da navegação automática,
         * que corresponde ao arquivo principal app.py.
         */
        [data-testid="stSidebarNav"] ul li:first-child {
            display: none !important;
        }

        /*
         * Estilização do link Home criado abaixo.
         */
        [data-testid="stSidebar"] [data-testid="stPageLink"] a {
            border: 1px solid rgba(0, 229, 255, 0.25);
            border-radius: 8px;
            padding: 0.55rem 0.75rem;
            margin-bottom: 0.35rem;
            transition:
                background-color 0.2s ease,
                border-color 0.2s ease;
        }

        [data-testid="stSidebar"] [data-testid="stPageLink"] a:hover {
            background: rgba(0, 229, 255, 0.08);
            border-color: rgba(0, 229, 255, 0.65);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # O destino continua sendo app.py; apenas o texto visível é Home.
    try:
        st.sidebar.page_link(
            "app.py",
            label="Home",
            icon=":material/home:",
        )
    except TypeError:
        # Compatibilidade com versões que não aceitam ícones Material.
        st.sidebar.page_link(
            "app.py",
            label="Home",
            icon="🏠",
        )


_renderizar_link_home_sidebar()
# <<< NAVEGACAO_HOME_FRONTEND <<<


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
        <h1>Cyber Threat Research <span style="white-space: nowrap;">3.9</span></h1>
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


# >>> PAINEL_FERRAMENTAS_OCULTO >>>
pass
# <<< PAINEL_FERRAMENTAS_OCULTO <<<

pages_path = Path(__file__).parent / "pages"

# Correção: painel antigo de ferramentas removido
tools = []
existing_tools = [
    tool for tool in tools
    if (pages_path / tool[3]).exists()
]

st.markdown("### Responsabilidades do usuário")

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
