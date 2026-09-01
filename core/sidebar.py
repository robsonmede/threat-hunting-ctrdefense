import streamlit as st

def render_sidebar():
    """Renderiza a sidebar com configurações de API e idioma."""
    with st.sidebar:
        st.markdown("""
            <div style="text-align: center; padding: 1rem 0;">
                <h3 style="color: #00f2fe; font-family: 'JetBrains Mono', monospace;">⚙️ Configurações</h3>
            </div>
        """, unsafe_allow_html=True)
        
        # Idioma
        lang_options = {"pt": "🇧🇷 Português", "en": "🇺🇸 English", "es": "🇪🇸 Español"}
        lang = st.selectbox("Idioma", options=list(lang_options.keys()), 
                           format_func=lambda x: lang_options[x], 
                           key="lang_select")
        
        # Dicionários de tradução
        translations = {
            "pt": {
                "app_title": "Cyber Threat Research - Caçador de Ameaças V3.9",
                "app_subtitle": "Análise de IOCs, reputação de IPs, inteligência de ameaças e OSINT automatizado",
                "
