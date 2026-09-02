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
    """Converte e formata valores numéricos para exibição."""

    if value is None:
        return "0"

    if isinstance(value, bool):
        return "0"

    try:
        if isinstance(value, float):
            value = int(value)

        return f"{int(str(value).replace(',', '').strip()):,}".replace(
            ",", "."
        )
    except (TypeError, ValueError, AttributeError):
        return "0"


def _to_int(value: Any, default: int = 0) -> int:
    """Converte um valor para inteiro sem interromper a aplicação."""

    if value is None or isinstance(value, bool):
        return default

    try:
        if isinstance(value, str):
            value = value.replace(".", "").replace(",", "").strip()

        return int(value)
    except (TypeError, ValueError):
        return default


def _first_value(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Retorna o primeiro valor existente entre várias chaves possíveis."""

    for key in keys:
        value = data.get(key)

        if value is not None and value != "":
            return value

    return default


def _normalize_breaches(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Normaliza a lista de vazamentos para diferentes formatos de API."""

    raw_breaches = _first_value(
        result,
        "breaches",
        "breach_list",
        "breach_details",
        "data",
        default=[],
    )

    if isinstance(raw_breaches, dict):
        raw_breaches = list(raw_breaches.values())

    if not isinstance(raw_breaches, (list, tuple)):
        return []

    normalized: list[dict[str, Any]] = []

    for item in raw_breaches:
        if isinstance(item, dict):
            normalized.append(item)
        elif isinstance(item, str):
            normalized.append(
                {
                    "name": item,
                    "title": item,
                }
            )

    return normalized


def _extract_breach_count(
    result: dict[str, Any],
    breaches: list[dict[str, Any]],
) -> int:
    """Obtém a quantidade de vazamentos do resultado normalizado."""

    value = _first_value(
        result,
        "breaches_found",
        "total_breaches",
        "breach_count",
        "count",
    )

    if value is not None:
        return _to_int(value)

    return len(breaches)


def _extract_exposed_records(
    result: dict[str, Any],
    breaches: list[dict[str, Any]],
) -> int:
    """Obtém a quantidade total de registros expostos."""

    value = _first_value(
        result,
        "total_records",
        "records_exposed",
        "exposed_records",
        "total_exposed",
    )

    if value is not None:
        return _to_int(value)

    total = 0

    for breach in breaches:
        total += _to_int(
            _first_value(
                breach,
                "records_exposed",
                "records",
                "exposed_records",
                "pwn_count",
                default=0,
            )
        )

    return total


def _save_query_history(
    email: str,
    status: str,
    breach_count: int,
    exposed_records: int,
) -> None:
    """Salva o resultado no histórico sem quebrar a interface."""

    history_item = {
        "timestamp": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "origem": "XposedOrNot",
        "e-mail": email,
        "status": status,
        "vazamentos": breach_count,
        "registros_expostos": exposed_records,
    }

    try:
        save_history(history_item)
    except Exception as exc:
        st.warning(
            "A consulta foi concluída, mas não foi possível "
            "salvar o histórico."
        )

        # Não exibe informações potencialmente sensíveis na interface.
        print(f"Falha ao salvar histórico: {exc}")


def _render_breach_details(
    breaches: list[dict[str, Any]],
) -> None:
    """Renderiza os detalhes dos vazamentos encontrados."""

    if not breaches:
        return

    st.subheader("Detalhes dos vazamentos")

    for index, breach in enumerate(breaches, start=1):
        title = _first_value(
            breach,
            "title",
            "name",
            "breach_name",
            "domain",
            default=f"Vazamento {index}",
        )

        date = _first_value(
            breach,
            "date",
            "breach_date",
            "added_date",
            "year",
            default="N/D",
        )

        records = _first_value(
            breach,
            "records_exposed",
            "records",
            "exposed_records",
            "pwn_count",
            default=0,
        )

        data_classes = _first_value(
            breach,
            "data_classes",
            "data_exposed",
            "exposed_data",
            "compromised_data",
            default=[],
        )

        if isinstance(data_classes, dict):
            data_classes = list(data_classes.keys())

        if isinstance(data_classes, (list, tuple, set)):
            data_classes_text = ", ".join(
                str(item)
                for item in data_classes
                if item is not None and str(item).strip()
            )
        else:
            data_classes_text = str(data_classes or "").strip()

        description = _first_value(
            breach,
            "description",
            "details",
            "summary",
            default="",
        )

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
                st.write(str(description))


def _run_xposedornot_query(
    email: str,
    api_key: Any,
) -> dict[str, Any]:
    """
    Executa a consulta de forma compatível com versões diferentes
    do serviço xposedornot.py.
    """

    try:
        result = query_xposedornot(
            email,
            api_key=api_key,
        )
    except TypeError as exc:
        # Compatibilidade com uma versão da função que ainda não possui
        # o parâmetro api_key.
        if "api_key" not in str(exc):
            raise

        result = query_xposedornot(email)

    if not isinstance(result, dict):
        return {
            "success": False,
            "error": "O serviço retornou uma resposta inesperada.",
        }

    return result


def _render_result(
    email: str,
    result: dict[str, Any],
) -> None:
    """Exibe o resultado normalizado da consulta."""

    error = result.get("error")

    if error:
        st.error(str(error))
        return

    success = result.get("success")

    if success is False:
        st.error(
            str(
                result.get(
                    "message",
                    "Não foi possível concluir a consulta.",
                )
            )
        )
        return

    breaches = _normalize_breaches(result)

    breach_count = _extract_breach_count(
        result,
        breaches,
    )

    exposed_records = _extract_exposed_records(
        result,
        breaches,
    )

    status = str(
        _first_value(
            result,
            "status",
            "risk_level",
            "risk",
            default=(
                "Vazamento encontrado"
                if breach_count > 0
                else "Nenhum vazamento encontrado"
            ),
        )
    )

    if breach_count > 0:
        st.warning(f"Resultado da consulta: {status}")
    else:
        st.success(
            "Nenhum vazamento conhecido foi encontrado "
            "para este endereço."
        )

    col1, col2, col3 = st.columns(3)

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

    with col3:
        st.metric(
            "Status",
            status,
        )

    _save_query_history(
        email=email,
        status=status,
        breach_count=breach_count,
        exposed_records=exposed_records,
    )

    if breaches:
        _render_breach_details(breaches)
    else:
        st.info(
            "A API não retornou detalhes individuais dos vazamentos."
        )


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
        st.error("Informe um endereço de e-mail válido.")

    else:
        api_key = st.session_state.get(
            "active_xposed_key"
        )

        with st.spinner(
            "Consultando bases de vazamentos..."
        ):
            try:
                result = _run_xposedornot_query(
                    email=email,
                    api_key=api_key,
                )
            except Exception as exc:
                print(f"Falha na consulta XposedOrNot: {exc}")

                result = {
                    "success": False,
                    "error": (
                        "Não foi possível concluir a consulta "
                        "ao XposedOrNot. Verifique a conexão "
                        "e tente novamente."
                    ),
                }

        _render_result(
            email=email,
            result=result,
        )


st.markdown(
    """
    <div class="ctr-footer">
        Os resultados dependem das bases consultadas pelo XposedOrNot.
        Utilize esta ferramenta somente para fins autorizados.
    </div>
    """,
    unsafe_allow_html=True,
)

