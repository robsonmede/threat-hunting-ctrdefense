import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from core.sidebar import render_sidebar


# ---------------------------------------------------------------------
# Configuração da página
# ---------------------------------------------------------------------

st.set_page_config(
    page_title="Cyber Threat Research V3.9",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------
# Inicialização
# ---------------------------------------------------------------------

apply_cyberpunk_css()
check_password()

# Deve ser executado antes de qualquer acesso às chaves da sessão.
lang_dict = render_sidebar()


# ---------------------------------------------------------------------
# Cabeçalho principal
# ---------------------------------------------------------------------

st.markdown(
    """
    <div class="ctr-header">
        <h1>Cyber Threat Research</h1>
        <p>Inteligência de Ameaças · Plataforma V3.9</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Status das APIs
# ---------------------------------------------------------------------

def render_status_card(nome: str, online: bool = True) -> None:
    status_class = "" if online else "offline"

    st.markdown(
        f"""
        <div class="status-card">
            <div class="status-name">{nome}</div>
            <div class="status-indicator {status_class}"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
status_columns = st.columns(5)

servicos = [
    ("VirusTotal", True),
    ("AbuseIPDB", True),
    ("urlscan.io", True),
    ("BotScout", True),
    ("OSINT", True),
]

for coluna, (nome, online) in zip(status_columns, servicos):
    with coluna:
        render_status_card(nome, online)

# ---------------------------------------------------------------------
# Hub de ferramentas
# ---------------------------------------------------------------------

def render_tool_card(
    icone: str,
    titulo: str,
    descricao: str,
) -> None:
    st.markdown(
        f"""
        <div class="tool-card">
            <div class="tool-icon">{icone}</div>
            <div class="tool-title">{titulo}</div>
            <div class="tool-description">{descricao}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# Primeira linha
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(
        """
        <a href="/pages/1_Extrator_IOCs" class="tool-card">
            <div class="tool-title">🔍 Extrator de IOCs</div>
            <div class="tool-desc">
                Extrai indicadores de compromisso de textos, logs,
                arquivos e URLs.
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        """
        <a href="/pages/2_AbuseIPDB" class="tool-card">
            <div class="tool-title">🛡️ AbuseIPDB</div>
            <div class="tool-desc">
                Consulta reputação de IPs, categorias de abuso e
                histórico de reports.
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        """
        <a href="/pages/3_VirusTotal" class="tool-card">
            <div class="tool-title">🧪 VirusTotal</div>
            <div class="tool-desc">
                Analisa arquivos, URLs, IPs e domínios com múltiplos
                motores antivírus.
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )


# Segunda linha
col4, col5, col6 = st.columns(3)

with col4:
    st.markdown(
        """
        <a href="/pages/4_Threat_Intelligence" class="tool-card">
            <div class="tool-title">🧠 Threat Intel</div>
            <div class="tool-desc">
                Correlação de dados, análise de CVEs e inteligência
                contextual.
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

with col5:
    st.markdown(
        """
        <a href="/pages/5_Relatorios" class="tool-card">
            <div class="tool-title">📊 Relatórios</div>
            <div class="tool-desc">
                Gera relatórios com histórico de consultas e métricas.
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

with col6:
    st.markdown(
        """
        <a href="/pages/6_Vazamento_Email" class="tool-card">
            <div class="tool-title">🔓 Vazamento de E-mail</div>
            <div class="tool-desc">
                Verifica se e-mails aparecem em vazamentos públicos
                de dados.
            </div>
        </a>
        """,
        unsafe_allow_html=True,
    )

st.markdown(
    "</div>",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Rodapé
# ---------------------------------------------------------------------

st.markdown(
    """
    <div class="ctr-footer">
        © 2024 CTR Defense · Uso autorizado e responsável
    </div>
    """,
    unsafe_allow_html=True,
)

