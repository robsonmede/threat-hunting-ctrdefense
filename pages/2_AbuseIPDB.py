from datetime import datetime, timezone

import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from services.abuseipdb import check_abuseipdb
from utils.export import save_history
from utils.helpers import is_valid_ip

from ui_sidebar import aplicar_sidebar



st.set_page_config(
    page_title="AbuseIPDB",
    page_icon="🛡️",
    layout="wide",
)

aplicar_sidebar()


apply_cyberpunk_css()
check_password()

st.title("🛡️ AbuseIPDB")
st.write(
    "Consulte a reputação e o histórico de denúncias de um IP."
)

ip = st.text_input(
    "Endereço IP",
    placeholder="Ex.: 8.8.8.8",
)

if st.button(
    "Consultar AbuseIPDB",
    type="primary",
):
    api_key = st.session_state.get(
        "active_abuse_key",
        "",
    ).strip()

    if not is_valid_ip(ip):
        st.error("Informe um IPv4 ou IPv6 válido.")
    elif not api_key:
        st.error(
            "Configure a chave do AbuseIPDB "
            "na barra lateral."
        )
    else:
        with st.spinner("Consultando AbuseIPDB..."):
            result = check_abuseipdb(
                api_key,
                ip.strip(),
            )

        if result.get("error"):
            st.error(result["error"])
        else:
            score = result.get(
                "score",
                result.get(
                    "abuse_confidence_score",
                    result.get(
                        "abuseConfidenceScore",
                        0,
                    ),
                ),
            )

            reports = result.get(
                "total_reports",
                result.get(
                    "totalReports",
                    0,
                ),
            )

            country = result.get(
                "country_code",
                result.get(
                    "countryCode",
                    "N/D",
                ),
            )

            col1, col2, col3 = st.columns(3)
            col1.metric("Score de abuso", score)
            col2.metric("Denúncias", reports)
            col3.metric("País", country)

            save_history(
                {
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat(timespec="seconds"),
                    "origem": "AbuseIPDB",
                    "indicador": ip.strip(),
                    "score": score,
                    "denuncias": reports,
                    "pais": country,
                }
            )

            with st.expander("Resposta completa"):
                st.json(result)
