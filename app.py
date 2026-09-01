import streamlit as st
from core.css import apply_cyberpunk_css
from core.auth import check_password
from core.sidebar import render_sidebar

# Configuração da página
st.set_page_config(
    page_title="Cyber Threat Research V3.9",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Aplicar CSS e autenticação
apply_cyberpunk_css()
check_password()

# Sidebar com API keys
lang_dict = render_sidebar()

# Cabeçalho principal
st.markdown(f'<div class="main-header">{lang_dict.get("app_title", "Cyber Threat Research")}</div>', unsafe_allow_html=True)
st.markdown(f'<div class="sub-header">{lang_dict.get("app_subtitle", "Análise de IOCs, reputação de IPs e inteligência de ameaças")}</div>', unsafe_allow_html=True)

# Status das APIs
st.markdown("### 📊 Status do Sistema")
col1, col2, col3, col4 = st.columns(4)
col1.metric("VirusTotal", "🟢" if st.session_state.get("active_vt_key") else "🟡")
col2.metric("AbuseIPDB", "🟢" if st.session_state.get("active_abuse_key") else "🟡")
col3.metric("urlscan.io", "🟢" if st.session_state.get("active_urlscan_key") else "⚪")
col4.metric("OSINT", "🟢")

# Hub de Ferramentas
st.markdown(f'### 🚀 {lang_dict.get("quick_hub", "Hub Rápido de Threat Intelligence")}')
st.markdown("Selecione uma ferramenta para análise detalhada:")

# Grid de ferramentas
st.markdown('<div class="tool-grid">', unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("""
        <a href="/pages/1_Extrator_IOCs" class="tool-card">
            <div class="tool-title">🔍 Extrator de IOCs</div>
            <div class="tool-desc">Extrai indicadores de compromisso de texto, logs, arquivos e URLs.</div>
        </a>
    """, unsafe_allow_html=True)
    
with col2:
    st.markdown("""
        <a href="/pages/2_AbuseIPDB" class="tool-card">
            <div class="tool-title">🛡️ AbuseIPDB</div>
            <div class="tool-desc">Consulta reputação de IPs, categorias de abuso e histórico de reports.</div>
        </a>
    """, unsafe_allow_html=True)
    
with col3:
    st.markdown("""
        <a href="/pages/3_VirusTotal" class="tool-card">
            <div class="tool-title">🧪 VirusTotal</div>
            <div class="tool-desc">Análise de arquivos, URLs, IPs e domínios com múltiplos motores antivírus.</div>
        </a>
    """, unsafe_allow_html=True)

col4, col5, col6 = st.columns(3)
with col4:
    st.markdown("""
        <a href="/pages/4_Threat_Intelligence" class="tool-card">
            <div class="tool-title">🧠 Threat Intel</div>
            <div class="tool-desc">Correlação de dados, análise de CVE e inteligência contextual.</div>
        </a>
    """, unsafe_allow_html=True)
    
with col5:
    st.markdown("""
        <a href="/pages/5_Relatorios" class="tool-card">
            <div class="tool-title">📊 Relatórios</div>
            <div class="tool-desc">Gera relatórios PDF/CSV/JSON com histórico de consultas e métricas.</div>
        </a>
    """, unsafe_allow_html=True)
    
with col6:
    st.markdown("""
        <a href="/pages/6_Vazamento_Email" class="tool-card">
            <div class="tool-title">🔓 Vazamento Email</div>
            <div class="tool-desc">Verifica se e-mails aparecem em vazamentos públicos de dados.</div>
        </a>
    """, unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)

# Seção de consulta rápida
st.markdown("### ⚡ Consulta Rápida OSINT")
quick_query = st.text_input("Digite IP, domínio, hash ou URL para análise rápida:")
if quick_query:
    with st.spinner("Consultando múltiplas fontes..."):
        # Aqui seria implementada a consulta multi-fonte
        st.info(f"Consulta rápida para: {quick_query}")
        st.write("Funcionalidade em desenvolvimento - use as páginas específicas para análise completa.")

# Rodapé
st.markdown(f'<div class="footer-text">{lang_dict.get("footer", "© 2024 CTR Defense - Uso sob responsabilidade.")}</div>', unsafe_allow_html=True)
