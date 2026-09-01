from datetime import datetime, timezone

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
)

apply_cyberpunk_css()
check_password()

st.title("🔓 Vazamento de E-mail")
st.write(
    "Verifique se um endereço de e-mail aparece "
    "em vazamentos conhecidos."
)

email = st.text_input(
    "Endereço de e-mail",
    placeholder="usuario@exemplo.com",
)

if st.button(
    "Verificar vazamentos",
    type="primary",
):
    email = email.strip().lower()

    if not is_valid_email(email):
        st.error("Informe um endereço de e-mail válido.")
    else:
        api_key = st.session_state.get(
            "active_xposed_key"
        )

        with st.spinner(
            "Consultando bases de vazamentos..."
        ):
            result = query_xposedornot(
                email,
                api_key=api_key,
            )

        if result.get("error"):
            st.error(result["error"])
        else:
            status = result.get(
                "status",
                "N/D",
            )

            breach_count = result.get(
                "breaches_found",
                0,
            )

            exposed_records = result.get(
                "total_records",
                0,
            )

            if breach_count:
                st.warning(
                    f"Resultado: {status}"
                )
            else:
                st.success(
                    "Nenhum vazamento conhecido foi encontrado."
                )

            col1, col2 = st.columns(2)
            col1.metric(
                "Vazamentos encontrados",
                breach_count,
            )
            col2.metric(
                "Registros expostos",
                exposed_records,
            )

            save_history(
                {
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat(timespec="seconds"),
                    "origem": "XposedOrNot",
                    "e-mail": email,
                    "status": status,
                    "vazamentos": breach_count,
                    "registros_expostos": exposed_records,
                }
            )

            breaches = result.get(
                "breach_list",
                [],
            )

            if breaches:
                st.subheader(
                    "Detalhes dos vazamentos"
                )

                for breach in breaches:
                    title = breach.get(
                        "name",
                        breach.get(
                            "title",
                            "Vazamento",
                        ),
                    )

                    with st.expander(title):
                        st.write(
                            f"**Data:** "
                            f"{breach.get('date', 'N/D')}"
                        )

                        st.write(
                            "**Registros expostos:** "
                            f"{breach.get('records_exposed', 0)}"
                        )

                        data_classes = breach.get(
                            "data_classes",
                            [],
                        )

                        if isinstance(
                            data_classes,
                            list,
                        ):
                            data_classes = ", ".join(
                                str(item)
                                for item in data_classes
                            )

                        st.write(
                            f"**Dados envolvidos:** "
                            f"{data_classes or 'N/D'}"
                        )

                        description = breach.get(
                            "description",
                            "",
                        )

                        if description:
                            st.write(description)
