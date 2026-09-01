# pages/6_Vazamento_Email.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from services.xposedornot import query_xposedornot
from utils.export import save_history
from utils.helpers import is_valid_email


st.set_page_config(
    page_title="Vazamento de E-mail",
    page_icon="🔓",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_cyberpunk_css()
check_password()


def _format_number(value: Any) -> str:
    """Formata números para exibição na interface."""

    try:
        return f"{int(value or 0):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "0"


def _save_query_history(
    email: str,
    status: str,
    breach_count: int,
    exposed_records: int,
) -> None:
    """
    Salva a consulta no histórico sem interromper a interface
    caso o armazenamento apresente algum problema.
    """

    history_item = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds"),
        "origem": "XposedOrNot",
        "e-mail": email,
        "status": status,
        "vazamentos": breach_count,
        "registros_expostos": exposed_records,
    }

    try:
        save_history(history_item)
    except Exception as exc:
        # O resultado da consulta não deve ser perdido caso o histórico
        # apresente falha de gravação.
        st.warning(
            "A consulta foi concluída, mas não foi possível "
            "salvar o histórico."
        )

        # Registra detalhes apenas no terminal, sem expor dados sensíveis
        # na interface.
        print(f"Falha ao salvar histórico: {exc}")


def _render_breach_details(breaches: list[Any]) -> None:
    """Renderiza os detalhes dos vazamentos encontrados."""

    if not breaches:
        return

    st.subheader("Detalhes dos vazamentos")

    for index, breach in enumerate(breaches, start=1):
        if not isinstance(breach, dict):
            continue

        title = (
            breach.get("title")
            or breach.get("name")
            or f"Vazamento {index}"
        )

        date = breach.get("date") or "N/D"

        records = breach.get(
            "records_exposed",
            0,
        )

        data_classes = breach.get(
            "data_classes",
            [],
        )

        if isinstance(data_classes, (list, tuple, set)):
            data_classes_text = ", ".join(
                str(item)
                for item in data_classes
                if item is not None
            )
        else:
            data_classes_text = str(
                data_classes or ""
            )

        description = str(
            breach.get("description")
            or ""
        ).strip()

        with st.expander(str(title)):
            st.write(f"**Data:** {date}")

            st.write(
                "**Registros expostos:** "
                f"{_format_number(records)}"
            )

            st.write(
                "**Dados envolvidos:** "
                f"{data_classes_text or 'N/D'}"
            )

            if description:
                st.write(description)


st.markdown(
    """
    <div class="ctr-header">
        <h1>🔓 Vazamento de E-mail</h1>
        <p>
            Verifique se um endereço de e-mail aparece
            em vazamentos conhecidos.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

email_input = st.text_input(
    "Endereço de e-mail",
    placeholder="usuario@exemplo.com",
    autocomplete="email",
)

if st.button(
    "🔍 Verificar vazamentos",
    type="primary",
    use_container_width=True,
):
    email = email_input.strip().lower()

    if not email:
        st.warning("Informe um endereço de e-mail.")

    elif not is_valid_email(email):
        st.error(
            "Informe um endereço de e-mail válido."
        )

    else:
        # A chave é obtida somente da sessão, alimentada pelo sidebar
        # ou pelo arquivo .streamlit/secrets.toml.
        api_key = st.session_state.get(
            "active_xposed_key"
        )

        with st.spinner(
            "Consultando bases de vazamentos..."
        ):
            try:
                result = query_xposedornot(
                    email,
                    api_key=api_key,
                )
            except Exception:
                result = {
                    "error": (
                        "Não foi possível concluir a consulta "
                        "ao XposedOrNot."
                    )
                }

        if not isinstance(result, dict):
            st.error(
                "O serviço retornou uma resposta inesperada."
            )

        elif result.get("error"):
            st.error(str(result["error"]))

        else:
            status = str(
                result.get("status")
                or "N/D"
            )

            try:
                breach_count = int(
                    result.get("breaches_found", 0)
                    or 0
                )
            except (TypeError, ValueError):
                breach_count = 0

            try:
                exposed_records = int(
                    result.get("total_records", 0)
                    or 0
                )
            except (TypeError, ValueError):
                exposed_records = 0

            if breach_count > 0:
                st.warning(
                    f"Resultado da consulta: {status}"
                )
            else:
                st.success(
                    "Nenhum vazamento conhecido "
                    "foi encontrado."
                )

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "Vazamentos encontrados",
                    _format_number(breach_count),
                )

            with col2:
                st.metric(
                    "Registros expostos",
                    _format_number(exposed_records),
                )

            _save_query_history(
                email=email,
                status=status,
                breach_count=breach_count,
                exposed_records=exposed_records,
            )

            breaches = result.get(
                "breach_list",
                [],
            )

            if not isinstance(breaches, list):
                breaches = []

            _render_breach_details(breaches)


st.markdown(
    """
    <div class="ctr-footer">
        Os resultados dependem das bases consultadas pelo XposedOrNot.
        Utilize esta ferramenta somente para fins autorizados.
    </div>
    """,
    unsafe_allow_html=True,
)
