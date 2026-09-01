import re
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from utils.export import export_download_button, save_history
from utils.helpers import detect_ioc_type, normalize_ioc


st.set_page_config(
    page_title="Extrator de IOCs",
    page_icon="🔎",
    layout="wide",
)

apply_cyberpunk_css()
check_password()

st.title("🔎 Extrator de IOCs")
st.write(
    "Extraia IPs, hashes, domínios, URLs e e-mails "
    "a partir de textos, logs ou relatórios."
)


def extract_iocs(text: str) -> list[dict[str, str]]:
    patterns = {
        "IP": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "Hash": r"\b[a-fA-F0-9]{32,64}\b",
        "E-mail": (
            r"\b[A-Za-z0-9._%+-]+@"
            r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "URL": r"https?://[^\s<>\"]+",
        "Domínio": (
            r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
            r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
        ),
    }

    unique_values: dict[str, str] = {}

    for pattern_type, pattern in patterns.items():
        matches = re.findall(pattern, text or "")

        for match in matches:
            value = normalize_ioc(match)

            if value:
                unique_values[value] = pattern_type

    result = []

    for value, pattern_type in sorted(
        unique_values.items()
    ):
        result.append(
            {
                "IOC": value,
                "Tipo encontrado": pattern_type,
                "Classificação": detect_ioc_type(value),
            }
        )

    return result


text = st.text_area(
    "Texto para análise",
    height=280,
    placeholder="Cole aqui o conteúdo que será analisado...",
)

if st.button(
    "Extrair indicadores",
    type="primary",
):
    result = extract_iocs(text)
    st.session_state["extracted_iocs"] = result

    if result:
        timestamp = datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds")

        for item in result:
            save_history(
                {
                    "timestamp": timestamp,
                    "origem": "Extrator de IOCs",
                    **item,
                }
            )

        st.success(
            f"{len(result)} indicador(es) encontrado(s)."
        )
    else:
        st.warning("Nenhum IOC foi identificado.")

iocs = st.session_state.get(
    "extracted_iocs",
    [],
)

if iocs:
    dataframe = pd.DataFrame(iocs)

    st.subheader("Indicadores encontrados")
    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True,
    )

    export_download_button(
        dataframe,
        filename="iocs_extraidos",
        key_prefix="iocs_extraidos",
    )
