from datetime import datetime, timezone

import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from services.virustotal import query_virustotal
from utils.export import save_history
from utils.helpers import detect_ioc_type


st.set_page_config(
    page_title="VirusTotal",
    page_icon="🧪",
    layout="wide",
)

apply_cyberpunk_css()
check_password()

st.title("🧪 VirusTotal")
st.write(
    "Consulte IPs, hashes, domínios e URLs no VirusTotal."
)

indicator = st.text_input(
    "Indicador",
    placeholder="Ex.: 8.8.8.8, hash, domínio ou URL",
)

if st.button(
    "Consultar VirusTotal",
    type="primary",
):
    api_key = st.session_state.get(
        "active_vt_key",
        "",
    ).strip()

    indicator_type = detect_ioc_type(indicator)

    if not api_key:
        st.error(
            "Configure a chave do VirusTotal "
            "na barra lateral."
        )
    elif indicator_type == "unknown":
        st.error(
            "Indicador não reconhecido. "
            "Informe um IP, hash, URL ou domínio válido."
        )
    else:
        try:
            with st.spinner("Consultando VirusTotal..."):
                result = query_virustotal(
                    api_key=api_key,
                    indicator=indicator.strip(),
                    indicator_type=indicator_type,
                )
        except TypeError:
            with st.spinner("Consultando VirusTotal..."):
                result = query_virustotal(
                    api_key,
                    indicator.strip(),
                )
        except Exception as exc:
            result = {
                "error": f"Erro na consulta: {exc}"
            }

        if result.get("error"):
            st.error(result["error"])
        else:
            stats = result.get(
                "last_analysis_stats",
                result.get(
                    "analysis_stats",
                    {},
                ),
            )

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

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Malicioso", malicious)
            col2.metric("Suspeito", suspicious)
            col3.metric("Inofensivo", harmless)
            col4.metric("Tipo", indicator_type.upper())

            save_history(
                {
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat(timespec="seconds"),
                    "origem": "VirusTotal",
                    "indicador": indicator.strip(),
                    "tipo": indicator_type,
                    "malicioso": malicious,
                    "suspeito": suspicious,
                    "inofensivo": harmless,
                }
            )

            with st.expander("Resposta completa"):
                st.json(result)
