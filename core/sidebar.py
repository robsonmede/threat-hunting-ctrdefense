# core/sidebar.py
"""
Sidebar centralizada do Cyber Threat Research.

Responsabilidades:
- Seleção de idioma;
- Entrada das chaves de API;
- Carregamento opcional das chaves via st.secrets;
- Armazenamento das chaves ativas em st.session_state;
- Retorno das configurações gerais da aplicação.

Arquivo esperado para secrets:
.streamlit/secrets.toml
"""

from __future__ import annotations

from typing import Any

import streamlit as st


# ---------------------------------------------------------------------
# Traduções
# ---------------------------------------------------------------------

TRANSLATIONS: dict[str, dict[str, str]] = {
    "pt": {
        "language": "Idioma",
        "language_name": "Português",
        "settings": "Configurações",
        "api_keys": "Chaves de API",
        "virus_total_key": "VirusTotal API Key",
        "abuse_ipdb_key": "AbuseIPDB API Key",
        "urlscan_key": "urlscan.io API Key",
        "botscout_key": "BotScout API Key",
        "optional_keys": (
            "As chaves são opcionais. Os módulos que não exigem "
            "autenticação podem funcionar em modo OSINT."
        ),
        "api_status": "Status das APIs",
        "configured": "Configurada",
        "not_configured": "Não configurada",
        "clear_keys": "Limpar chaves da sessão",
        "keys_cleared": "Chaves removidas da sessão.",
        "about": "Sobre o projeto",
        "responsibility": (
            "Utilize esta ferramenta somente em atividades autorizadas "
            "de pesquisa, defesa e resposta a incidentes."
        ),
        "app_title": "Cyber Threat Research",
        "app_subtitle": "Inteligência de Ameaças V3.9",
        "home": "🏠 Início",
        "quick_hub": "🔗 Ferramentas Rápidas",
        "footer": "© 2024 CTR Defense - Uso sob responsabilidade.",
    },
    "en": {
        "language": "Language",
        "language_name": "English",
        "settings": "Settings",
        "api_keys": "API Keys",
        "virus_total_key": "VirusTotal API Key",
        "abuse_ipdb_key": "AbuseIPDB API Key",
        "urlscan_key": "urlscan.io API Key",
        "botscout_key": "BotScout API Key",
        "optional_keys": (
            "API keys are optional. Modules that do not require "
            "authentication can operate in OSINT mode."
        ),
        "api_status": "API Status",
        "configured": "Configured",
        "not_configured": "Not configured",
        "clear_keys": "Clear session keys",
        "keys_cleared": "Session keys removed.",
        "about": "About the project",
        "responsibility": (
            "Use this tool only for authorized research, defense "
            "and incident-response activities."
        ),
        "app_title": "Cyber Threat Research",
        "app_subtitle": "Threat Intelligence V3.9",
        "home": "🏠 Home",
        "quick_hub": "🔗 Quick Tools",
        "footer": "© 2024 CTR Defense - Use at your own responsibility.",
    },
    "es": {
        "language": "Idioma",
        "language_name": "Español",
        "settings": "Configuración",
        "api_keys": "Claves de API",
        "virus_total_key": "VirusTotal API Key",
        "abuse_ipdb_key": "AbuseIPDB API Key",
        "urlscan_key": "urlscan.io API Key",
        "botscout_key": "BotScout API Key",
        "optional_keys": (
            "Las claves son opcionales. Los módulos que no requieren "
            "autenticación pueden funcionar en modo OSINT."
        ),
        "api_status": "Estado de las APIs",
        "configured": "Configurada",
        "not_configured": "No configurada",
        "clear_keys": "Limpiar claves de la sesión",
        "keys_cleared": "Claves eliminadas de la sesión.",
        "about": "Sobre el proyecto",
        "responsibility": (
            "Utilice esta herramienta únicamente en actividades autorizadas "
            "de investigación, defensa y respuesta a incidentes."
        ),
        "app_title": "Cyber Threat Research",
        "app_subtitle": "Inteligencia de Amenazas V3.9",
        "home": "🏠 Inicio",
        "quick_hub": "🔗 Herramientas Rápidas",
        "footer": "© 2024 CTR Defense - Uso bajo responsabilidad.",
    },
}


# ---------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------

def _get_secret(name: str, default: str = "") -> str:
    """
    Obtém um valor de st.secrets sem gerar erro quando o segredo não existe.
    """
    try:
        value = st.secrets.get(name, default)
    except Exception:
        value = default

    if value is None:
        return default

    return str(value).strip()


def _is_configured(value: str) -> bool:
    """Retorna True quando existe uma chave não vazia."""
    return bool(value and value.strip())


def _initialize_session_keys() -> None:
    """
    Inicializa as chaves ativas somente quando ainda não existem na sessão.

    Isso evita substituir uma chave digitada pelo usuário a cada rerun
    do Streamlit.
    """
    defaults = {
        "active_vt_key": _get_secret("VIRUSTOTAL_API_KEY"),
        "active_abuse_key": _get_secret("ABUSEIPDB_API_KEY"),
        "active_urlscan_key": _get_secret("URLSCAN_API_KEY"),
        "active_botscout_key": _get_secret("BOTSCOUT_API_KEY"),
    }

    for session_key, default_value in defaults.items():
        if session_key not in st.session_state:
            st.session_state[session_key] = default_value


def _render_api_status(text: dict[str, str]) -> None:
    """Exibe o status resumido das chaves configuradas."""
    api_keys = {
        "VirusTotal": st.session_state.get("active_vt_key", ""),
        "AbuseIPDB": st.session_state.get("active_abuse_key", ""),
        "urlscan.io": st.session_state.get("active_urlscan_key", ""),
        "BotScout": st.session_state.get("active_botscout_key", ""),
    }

    with st.expander(f"📡 {text['api_status']}", expanded=False):
        for service_name, key in api_keys.items():
            if _is_configured(key):
                st.success(f"✅ {service_name}: {text['configured']}")
            else:
                st.warning(f"⚠️ {service_name}: {text['not_configured']}")


def _clear_session_keys() -> None:
    """Remove as chaves ativas armazenadas na sessão."""
    for key in (
        "active_vt_key",
        "active_abuse_key",
        "active_urlscan_key",
        "active_botscout_key",
    ):
        st.session_state.pop(key, None)


# ---------------------------------------------------------------------
# Função pública
# ---------------------------------------------------------------------

def render_sidebar() -> dict[str, Any]:
    """
    Renderiza a barra lateral e retorna as configurações da aplicação.

    Returns:
        dict[str, Any]: Configurações de título, idioma, navegação e rodapé.
    """
    _initialize_session_keys()

    with st.sidebar:
        st.markdown(
            """
            <style>
            [data-testid="stSidebar"] {
                min-width: 290px;
                max-width: 360px;
            }

            .sidebar-title {
                text-align: center;
                color: #00f2fe;
                font-weight: 700;
                letter-spacing: 1px;
                margin-bottom: 0;
            }

            .sidebar-subtitle {
                text-align: center;
                color: #9ca3af;
                font-size: 0.85rem;
                margin-top: 0.25rem;
                margin-bottom: 1rem;
            }
            </style>

            <div>
                <h3 class="sidebar-title">⚡ CTR</h3>
                <p class="sidebar-subtitle">Cyber Threat Research</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # -------------------------------------------------------------
        # Idioma
        # -------------------------------------------------------------
        language_options = {
            "pt": "🇧🇷 Português",
            "en": "🇺🇸 English",
            "es": "🇪🇸 Español",
        }

        current_language = st.session_state.get("language", "pt")
        if current_language not in language_options:
            current_language = "pt"

        selected_language = st.selectbox(
            "🌐 Idioma / Language / Idioma",
            options=list(language_options.keys()),
            index=list(language_options.keys()).index(current_language),
            format_func=lambda code: language_options[code],
            key="language",
        )

        text = TRANSLATIONS.get(
            selected_language,
            TRANSLATIONS["pt"],
        )

        st.divider()

        # -------------------------------------------------------------
        # Chaves de API
        # -------------------------------------------------------------
        st.markdown(f"### 🔑 {text['api_keys']}")

        st.session_state["active_vt_key"] = st.text_input(
            text["virus_total_key"],
            type="password",
            value=st.session_state.get("active_vt_key", ""),
            key="vt_api_key_input",
            help="Chave utilizada para consultas ao VirusTotal.",
        )

        st.session_state["active_abuse_key"] = st.text_input(
            text["abuse_ipdb_key"],
            type="password",
            value=st.session_state.get("active_abuse_key", ""),
            key="abuse_api_key_input",
            help="Chave utilizada para consultas ao AbuseIPDB.",
        )

        st.session_state["active_urlscan_key"] = st.text_input(
            text["urlscan_key"],
            type="password",
            value=st.session_state.get("active_urlscan_key", ""),
            key="urlscan_api_key_input",
            help="Chave utilizada para consultas ao urlscan.io.",
        )

        st.session_state["active_botscout_key"] = st.text_input(
            text["botscout_key"],
            type="password",
            value=st.session_state.get("active_botscout_key", ""),
            key="botscout_api_key_input",
            help="Chave utilizada para consultas ao BotScout.",
        )

        st.caption(f"ℹ️ {text['optional_keys']}")

        # -------------------------------------------------------------
        # Status e limpeza
        # -------------------------------------------------------------
        _render_api_status(text)

        if st.button(
            f"🧹 {text['clear_keys']}",
            use_container_width=True,
        ):
            _clear_session_keys()
            st.success(text["keys_cleared"])
            st.rerun()

        st.divider()

        with st.expander(f"ℹ️ {text['about']}", expanded=False):
            st.caption(text["responsibility"])

        st.markdown(
            f"""
            <div style="
                text-align: center;
                color: #7f8c8d;
                font-size: 0.75rem;
                padding-top: 1rem;
            ">
                {text["footer"]}
            </div>
            """,
            unsafe_allow_html=True,
        )

    return {
        "app_title": text["app_title"],
        "app_subtitle": text["app_subtitle"],
        "language": selected_language,
        "home": text["home"],
        "quick_hub": text["quick_hub"],
        "footer": text["footer"],
        "active_vt_key": st.session_state.get("active_vt_key", ""),
        "active_abuse_key": st.session_state.get("active_abuse_key", ""),
        "active_urlscan_key": st.session_state.get(
            "active_urlscan_key",
            "",
        ),
        "active_botscout_key": st.session_state.get(
            "active_botscout_key",
            "",
        ),
    }
