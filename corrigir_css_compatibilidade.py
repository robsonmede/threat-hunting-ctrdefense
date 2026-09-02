from __future__ import annotations

from pathlib import Path
from datetime import datetime
import shutil
import py_compile


ROOT = Path(__file__).resolve().parent
CSS_FILE = ROOT / "core" / "css.py"


COMPATIBILITY_CODE = r'''

# ---------------------------------------------------------------------
# Compatibilidade com páginas antigas
# ---------------------------------------------------------------------

def apply_cyberpunk_css() -> None:
    """
    Compatibilidade com páginas que utilizam:

        from core.css import apply_cyberpunk_css

    Tenta utilizar as funções de aplicação de CSS já existentes no módulo.
    """
    import streamlit as st

    # Evita aplicar o CSS várias vezes na mesma execução.
    if st.session_state.get("_cyberpunk_css_applied", False):
        return

    # Procura funções já existentes no core.css.
    candidate_functions = (
        "inject_css",
        "apply_css",
        "load_css",
        "render_css",
        "apply_styles",
    )

    for function_name in candidate_functions:
        function = globals().get(function_name)

        if callable(function) and function_name != "apply_cyberpunk_css":
            try:
                function()
                st.session_state["_cyberpunk_css_applied"] = True
                return
            except TypeError:
                # Algumas versões podem exigir argumentos.
                continue
            except Exception:
                # Se a função antiga falhar, usa o CSS mínimo abaixo.
                break

    # Fallback visual para garantir que a página não quebre.
    st.markdown(
        """
        <style>
        :root {
            --cyber-bg: #080b14;
            --cyber-panel: #111827;
            --cyber-border: #243244;
            --cyber-primary: #00e5ff;
            --cyber-secondary: #a855f7;
            --cyber-text: #e5f6ff;
            --cyber-muted: #94a3b8;
        }

        .stApp {
            background:
                radial-gradient(
                    circle at top right,
                    rgba(0, 229, 255, 0.08),
                    transparent 32%
                ),
                linear-gradient(135deg, #080b14 0%, #0f172a 100%);
            color: var(--cyber-text);
        }

        [data-testid="stSidebar"] {
            background: #0a0f1c;
            border-right: 1px solid var(--cyber-border);
        }

        [data-testid="stMetric"] {
            background: rgba(17, 24, 39, 0.85);
            border: 1px solid var(--cyber-border);
            border-radius: 12px;
            padding: 14px;
        }

        div.stButton > button {
            border: 1px solid var(--cyber-primary);
            border-radius: 8px;
            background: rgba(0, 229, 255, 0.08);
            color: var(--cyber-text);
        }

        div.stButton > button:hover {
            border-color: var(--cyber-secondary);
            color: white;
            box-shadow: 0 0 14px rgba(0, 229, 255, 0.25);
        }

        .cyber-card,
        .tool-card,
        .status-card {
            background: rgba(17, 24, 39, 0.88);
            border: 1px solid var(--cyber-border);
            border-radius: 12px;
            padding: 18px;
            margin: 10px 0;
        }

        h1, h2, h3 {
            color: var(--cyber-primary);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.session_state["_cyberpunk_css_applied"] = True
'''


def create_backup(path: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(
        f"{path.stem}.backup_{timestamp}{path.suffix}"
    )
    shutil.copy2(path, backup)
    return backup


def fix_css() -> None:
    if not CSS_FILE.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {CSS_FILE}"
        )

    content = CSS_FILE.read_text(encoding="utf-8")

    if "def apply_cyberpunk_css(" in content:
        print("A função apply_cyberpunk_css já existe.")
        return

    backup = create_backup(CSS_FILE)

    content = content.rstrip() + COMPATIBILITY_CODE + "\n"
    CSS_FILE.write_text(content, encoding="utf-8")

    print("Função apply_cyberpunk_css adicionada com sucesso.")
    print(f"Backup criado em: {backup}")


def validate_css() -> None:
    try:
        py_compile.compile(
            str(CSS_FILE),
            doraise=True,
        )
        print("Sintaxe de core/css.py validada com sucesso.")
    except py_compile.PyCompileError as error:
        print("Erro de sintaxe em core/css.py:")
        print(error)
        raise


if __name__ == "__main__":
    print("=== Correção de compatibilidade do CSS ===")

    fix_css()
    validate_css()

    print("\nCorreção concluída.")
    print("Reinicie o Streamlit:")
    print("  pkill -f streamlit")
    print("  streamlit run app.py")

