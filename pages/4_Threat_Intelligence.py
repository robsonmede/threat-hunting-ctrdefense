from datetime import datetime, timezone

import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from utils.export import save_history
from utils.helpers import detect_ioc_type

from ui_sidebar import aplicar_sidebar



st.set_page_config(
    page_title="Threat Intelligence",
    page_icon="🧠",
    layout="wide",
)

aplicar_sidebar()


apply_cyberpunk_css()
check_password()

st.title("🧠 Threat Intelligence")
st.write(
    "Central de triagem e correlação de indicadores "
    "de comprometimento."
)

query = st.text_input(
    "Indicador, entidade ou CVE",
    placeholder="Ex.: CVE-2024-1234, IP, domínio ou hash",
)

if st.button(
    "Classificar indicador",
    type="primary",
):
    query = query.strip()

    if not query:
        st.warning("Informe um valor para análise.")
    else:
        ioc_type = detect_ioc_type(query)

        st.success(
            f"Tipo identificado: **{ioc_type.upper()}**"
        )

        save_history(
            {
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(timespec="seconds"),
                "origem": "Threat Intelligence",
                "indicador": query,
                "tipo": ioc_type,
            }
        )

        if ioc_type == "ip":
            st.info(
                "Use AbuseIPDB para consultar a reputação "
                "deste endereço."
            )
        elif ioc_type in {
            "hash",
            "url",
            "domain",
        }:
            st.info(
                "Use VirusTotal para realizar a análise "
                "detalhada deste indicador."
            )
        elif query.upper().startswith("CVE-"):
            st.info(
                "Este valor aparenta ser um identificador "
                "de vulnerabilidade CVE."
            )
        else:
            st.warning(
                "O valor não corresponde a um formato conhecido "
                "de IOC."
            )
