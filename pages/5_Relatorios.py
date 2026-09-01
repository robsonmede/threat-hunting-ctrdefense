import pandas as pd
import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from utils.export import export_download_button


st.set_page_config(
    page_title="Relatórios",
    page_icon="📊",
    layout="wide",
)

apply_cyberpunk_css()
check_password()

st.title("📊 Relatórios")
st.write(
    "Consulte e exporte o histórico das análises realizadas."
)

history = st.session_state.get(
    "query_history",
    [],
)

if not history:
    st.info(
        "Nenhum registro disponível. "
        "Execute uma consulta para criar o relatório."
    )
else:
    dataframe = pd.json_normalize(history)

    st.metric(
        "Total de registros",
        len(dataframe),
    )

    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True,
    )

    export_download_button(
        dataframe,
        filename="relatorio_threat_intel",
        key_prefix="relatorio_threat_intel",
    )

    st.divider()

    if st.button(
        "Limpar histórico",
        type="secondary",
    ):
        st.session_state["query_history"] = []
        st.rerun()
