from __future__ import annotations

import streamlit as st


def aplicar_sidebar() -> None:
    """Aplica o mesmo estilo de sidebar em todas as páginas."""

    st.markdown(
        """
        <style>
        /* Sidebar */
        [data-testid="stSidebar"] {
            background:
                linear-gradient(
                    180deg,
                    #071426 0%,
                    #0b1f35 55%,
                    #071426 100%
                );
            border-right: 1px solid rgba(56, 189, 248, 0.22);
        }

        [data-testid="stSidebar"] > div:first-child {
            padding-top: 1.2rem;
        }

        /* Textos da sidebar */
        [data-testid="stSidebar"] * {
            color: #e6f4ff;
        }

        /* Links da navegação */
        [data-testid="stSidebarNav"] a {
            border-radius: 10px;
            margin: 4px 8px;
            padding: 10px 12px;
            transition:
                background-color 0.2s ease,
                border-color 0.2s ease,
                transform 0.2s ease;
        }

        [data-testid="stSidebarNav"] a:hover {
            background: rgba(14, 165, 233, 0.13);
            border: 1px solid rgba(56, 189, 248, 0.30);
            transform: translateX(2px);
        }

        /* Página selecionada */
        [data-testid="stSidebarNav"] a[aria-current="page"] {
            background:
                linear-gradient(
                    90deg,
                    rgba(14, 165, 233, 0.24),
                    rgba(37, 99, 235, 0.14)
                );
            border: 1px solid rgba(56, 189, 248, 0.45);
            box-shadow: 0 0 16px rgba(14, 165, 233, 0.10);
        }

        [data-testid="stSidebarNav"] a[aria-current="page"] span {
            color: #7dd3fc !important;
            font-weight: 700;
        }

        /* Título da navegação */
        [data-testid="stSidebarNav"]::before {
            content: "CTR DEFENSE 3.9";
            display: block;
            color: #7dd3fc;
            font-size: 0.82rem;
            font-weight: 800;
            letter-spacing: 0.12rem;
            margin: 4px 20px 18px;
        }

        /* Separadores */
        [data-testid="stSidebar"] hr {
            border-color: rgba(148, 163, 184, 0.20);
        }

        /* Botões */
        [data-testid="stSidebar"] button {
            border-radius: 9px;
            border-color: rgba(56, 189, 248, 0.30);
        }

        /* Rodapé */
        .ctr-sidebar-footer {
            margin-top: 2rem;
            padding: 14px 12px;
            border-top: 1px solid rgba(148, 163, 184, 0.18);
            color: #94a3b8;
            font-size: 0.74rem;
            line-height: 1.5;
            text-align: center;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown(
            """
            <div class="ctr-sidebar-footer">
                Cyber Threat Research<br>
                Versão 3.9
            </div>
            """,
            unsafe_allow_html=True,
        )

