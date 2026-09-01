from __future__ import annotations

import io
from typing import Any

import pandas as pd
import streamlit as st


def records_to_dataframe(records: Any) -> pd.DataFrame:
    """Converte listas ou dicionários em DataFrame."""
    if isinstance(records, pd.DataFrame):
        return records

    if isinstance(records, list):
        return pd.json_normalize(records)

    if isinstance(records, dict):
        return pd.json_normalize(records)

    return pd.DataFrame({"valor": [records]})


def dataframe_to_csv(dataframe: pd.DataFrame) -> bytes:
    return dataframe.to_csv(
        index=False
    ).encode("utf-8-sig")


def dataframe_to_json(dataframe: pd.DataFrame) -> bytes:
    return dataframe.to_json(
        orient="records",
        force_ascii=False,
        indent=2,
    ).encode("utf-8")


def dataframe_to_excel(dataframe: pd.DataFrame) -> bytes:
    output = io.BytesIO()

    with pd.ExcelWriter(
        output,
        engine="openpyxl",
    ) as writer:
        dataframe.to_excel(
            writer,
            index=False,
            sheet_name="Relatorio",
        )

    return output.getvalue()


def export_download_button(
    dataframe: pd.DataFrame,
    filename: str = "relatorio",
    key_prefix: str = "export",
) -> None:
    """Exibe botões para baixar CSV, JSON e Excel."""

    if dataframe.empty:
        st.info("Não há dados para exportar.")
        return

    col_csv, col_json, col_excel = st.columns(3)

    with col_csv:
        st.download_button(
            label="Baixar CSV",
            data=dataframe_to_csv(dataframe),
            file_name=f"{filename}.csv",
            mime="text/csv",
            key=f"{key_prefix}_csv",
        )

    with col_json:
        st.download_button(
            label="Baixar JSON",
            data=dataframe_to_json(dataframe),
            file_name=f"{filename}.json",
            mime="application/json",
            key=f"{key_prefix}_json",
        )

    with col_excel:
        try:
            excel_data = dataframe_to_excel(dataframe)

            st.download_button(
                label="Baixar Excel",
                data=excel_data,
                file_name=f"{filename}.xlsx",
                mime=(
                    "application/vnd.openxmlformats-officedocument."
                    "spreadsheetml.sheet"
                ),
                key=f"{key_prefix}_excel",
            )
        except ImportError:
            st.warning(
                "Instale openpyxl para habilitar o Excel."
            )


def save_history(record: dict[str, Any]) -> None:
    """Salva uma consulta no histórico da sessão."""
    history = st.session_state.setdefault(
        "query_history",
        [],
    )
    history.append(record)
