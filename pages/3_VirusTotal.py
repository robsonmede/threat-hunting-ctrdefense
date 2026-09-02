# pages/3_VirusTotal.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from services.virustotal import (
    detect_ioc_type,
    query_virustotal,
)
from utils.export import save_history

from ui_sidebar import aplicar_sidebar



st.set_page_config(
    page_title="VirusTotal",
    page_icon="🧪",
    layout="wide",
)

aplicar_sidebar()


apply_cyberpunk_css()
check_password()


def _get_analysis_stats(result: dict[str, Any]) -> dict[str, Any]:
    """
    Obtém as estatísticas da análise em diferentes formatos
    possíveis de resposta.
    """

    stats = result.get("stats")

    if isinstance(stats, dict):
        return stats

    attributes = result.get("attributes", {})

    if isinstance(attributes, dict):
        stats = attributes.get("last_analysis_stats")

        if isinstance(stats, dict):
            return stats

    data = result.get("data", {})

    if isinstance(data, dict):
        data_attributes = data.get("data", {}).get(
            "attributes",
            {},
        )

        if isinstance(data_attributes, dict):
            stats = data_attributes.get("last_analysis_stats")

            if isinstance(stats, dict):
                return stats

    return {}


def _get_result_error(result: Any) -> str | None:
    """Obtém uma mensagem de erro padronizada."""

    if not isinstance(result, dict):
        return "Resposta inválida recebida do VirusTotal."

    if result.get("success") is False:
        return str(
            result.get(
                "error",
                "Não foi possível concluir a consulta.",
            )
        )

    if result.get("error"):
        return str(result["error"])

    return None


st.title("🧪 VirusTotal")

st.write(
    "Consulte IPs, hashes, domínios e URLs no VirusTotal."
)

indicator = st.text_input(
    "Indicador",
    placeholder=(
        "Ex.: 8.8.8.8, hash, domínio ou URL"
    ),
)

if st.button(
    "Consultar VirusTotal",
    type="primary",
):
    indicator = indicator.strip()

    if not indicator:
        st.warning(
            "Informe um indicador antes de realizar a consulta."
        )
        st.stop()

    api_key = st.session_state.get(
        "active_vt_key",
        "",
    )

    if not isinstance(api_key, str):
        api_key = str(api_key or "")

    api_key = api_key.strip()

    if not api_key:
        st.error(
            "Configure a chave do VirusTotal "
            "na barra lateral."
        )
        st.stop()

    try:
        indicator_type = detect_ioc_type(
            indicator,
            "auto",
        )

    except (ValueError, TypeError):
        indicator_type = "unknown"

    if indicator_type == "unknown":
        st.error(
            "Indicador não reconhecido. "
            "Informe um IP, hash, URL ou domínio válido."
        )
        st.stop()

    try:
        with st.spinner(
            "Consultando VirusTotal..."
        ):
            result = query_virustotal(
                api_key=api_key,
                ioc=indicator,
                ioc_type=indicator_type,
            )

    except Exception as exc:
        result = {
            "success": False,
            "error": f"Erro inesperado na consulta: {exc}",
        }

    error_message = _get_result_error(result)

    if error_message:
        st.error(error_message)
        st.stop()

    stats = _get_analysis_stats(result)

    malicious = stats.get(
        "malicious",
        result.get("malicious", 0),
    )

    suspicious = stats.get(
        "suspicious",
        result.get("suspicious", 0),
    )

    harmless = stats.get(
        "harmless",
        result.get("harmless", 0),
    )

    undetected = stats.get(
        "undetected",
        result.get("undetected", 0),
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Malicioso",
        malicious,
    )

    col2.metric(
        "Suspeito",
        suspicious,
    )

    col3.metric(
        "Inofensivo",
        harmless,
    )

    col4.metric(
        "Não detectado",
        undetected,
    )

    st.caption(
        f"Tipo identificado: **{indicator_type.upper()}**"
    )

    try:
        save_history(
            {
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(
                    timespec="seconds"
                ),
                "origem": "VirusTotal",
                "indicador": indicator,
                "tipo": indicator_type,
                "malicioso": malicious,
                "suspeito": suspicious,
                "inofensivo": harmless,
                "nao_detectado": undetected,
            }
        )

    except Exception as exc:
        st.warning(
            f"A consulta foi concluída, mas não foi possível "
            f"salvar o histórico: {exc}"
        )

    with st.expander(
        "Resposta completa",
        expanded=False,
    ):
        st.json(result)
