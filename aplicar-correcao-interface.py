from __future__ import annotations

import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CORE_DIR = ROOT / "core"
PAGES_DIR = ROOT / "pages"
STREAMLIT_DIR = ROOT / ".streamlit"
BACKUP_DIR = ROOT / "_backup_correcao"

APP_FILE = ROOT / "app.py"
AUTH_FILE = CORE_DIR / "auth.py"
CSS_FILE = CORE_DIR / "css.py"
SIDEBAR_FILE = CORE_DIR / "sidebar.py"
GITIGNORE_FILE = ROOT / ".gitignore"
SECRETS_EXAMPLE = STREAMLIT_DIR / "secrets.example.toml"


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def backup_file(path: Path) -> None:
    if not path.exists():
        return

    backup_path = BACKUP_DIR / timestamp() / path.relative_to(ROOT)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, backup_path)

    print(f"[BACKUP] {path} -> {backup_path}")


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup_file(path)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
    print(f"[OK] Arquivo atualizado: {path}")


AUTH_PY = r'''from __future__ import annotations

import hashlib
import hmac
from typing import Any

import streamlit as st


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _get_users() -> dict[str, Any]:
    try:
        auth = st.secrets.get("auth", {})
        return dict(auth.get("users", {}))
    except Exception:
        return {}


def authenticate(username: str, password: str) -> bool:
    username = username.strip()

    if not username or not password:
        return False

    user_data = _get_users().get(username)

    if not user_data:
        return False

    stored_hash = str(user_data.get("password_hash", "")).strip()

    if not stored_hash:
        return False

    return hmac.compare_digest(
        _hash_password(password),
        stored_hash,
    )


def get_user_role(username: str) -> str:
    user_data = _get_users().get(username, {})
    return str(user_data.get("role", "user"))


def initialize_auth_state() -> None:
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("username", "")
    st.session_state.setdefault("user_role", "user")


def login_form() -> None:
    st.markdown(
        """
        <div class="login-wrapper">
            <div class="login-brand">⚡</div>
            <h1>Cyber Threat Research</h1>
            <p>Plataforma de inteligência e análise de ameaças</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("login_form", clear_on_submit=False):
        username = st.text_input(
            "Usuário",
            placeholder="Digite seu usuário",
            autocomplete="username",
        )

        password = st.text_input(
            "Senha",
            type="password",
            placeholder="Digite sua senha",
            autocomplete="current-password",
        )

        submitted = st.form_submit_button(
            "Entrar",
            use_container_width=True,
        )

    if submitted:
        if authenticate(username, password):
            st.session_state.authenticated = True
            st.session_state.username = username.strip()
            st.session_state.user_role = get_user_role(username.strip())
            st.rerun()
        else:
            st.error("Usuário ou senha inválidos.")


def require_login() -> bool:
    initialize_auth_state()

    if st.session_state.authenticated:
        return True

    login_form()
    return False


def logout() -> None:
    keys = (
        "authenticated",
        "username",
        "user_role",
        "vt_api_key",
        "abuseipdb_api_key",
        "urlscan_api_key",
        "botscout_api_key",
    )

    for key in keys:
        st.session_state.pop(key, None)

    st.rerun()
'''


CSS_PY = r'''from __future__ import annotations

import streamlit as st


def load_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --bg: #060b14;
            --panel: #0d1728;
            --panel-hover: #12223a;
            --border: #203b5d;
            --cyan: #00d9ff;
            --blue: #3d8bfd;
            --text: #e8f1ff;
            --muted: #91a4be;
        }

        .stApp {
            background:
                radial-gradient(
                    circle at 50% 0%,
                    rgba(0, 217, 255, .10),
                    transparent 35%
                ),
                var(--bg);
            color: var(--text);
        }

        [data-testid="stSidebar"] {
            background: #1d222d;
            border-right: 1px solid #29364a;
        }

        [data-testid="stSidebar"] * {
            color: var(--text);
        }

        .hero-home {
            text-align: center;
            padding: 1.5rem 1rem 2rem;
        }

        .hero-badge {
            color: var(--cyan);
            font-size: .78rem;
            font-weight: 700;
            letter-spacing: .18em;
            margin-bottom: .7rem;
        }

        .hero-home h1 {
            margin: 0;
            color: var(--cyan);
            font-size: clamp(2.2rem, 5vw, 4.1rem);
            font-weight: 800;
            text-shadow: 0 0 25px rgba(0, 217, 255, .35);
        }

        .hero-home p {
            max-width: 760px;
            margin: .8rem auto 0;
            color: var(--muted);
            font-size: 1.05rem;
        }

        .home-tool-card {
            min-height: 170px;
            margin-bottom: 1rem;
            padding: 1.35rem;
            border: 1px solid var(--border);
            border-radius: 14px;
            background: linear-gradient(145deg, var(--panel), #09111e);
            transition: .2s ease;
        }

        .home-tool-card:hover {
            border-color: var(--cyan);
            background: var(--panel-hover);
            transform: translateY(-2px);
            box-shadow: 0 0 22px rgba(0, 217, 255, .12);
        }

        .home-tool-icon {
            font-size: 1.8rem;
            margin-bottom: .5rem;
        }

        .home-tool-card h3 {
            color: var(--cyan);
            margin: 0 0 .55rem;
            font-size: 1.08rem;
        }

        .home-tool-card p {
            color: #a9c3e7;
            line-height: 1.55;
            margin: 0;
        }

        .home-notice {
            display: flex;
            gap: .7rem;
            align-items: flex-start;
            margin-top: 1.2rem;
            padding: 1rem;
            border-left: 3px solid var(--blue);
            border-radius: 8px;
            background: rgba(61, 139, 253, .08);
            color: var(--muted);
        }

        .home-notice strong {
            color: #a9d1ff;
            white-space: nowrap;
        }

        .home-footer {
            margin-top: 3rem;
            padding: 1.2rem 0;
            border-top: 1px solid var(--border);
            text-align: center;
            color: #7188a8;
            font-size: .82rem;
        }

        .login-wrapper {
            max-width: 620px;
            margin: 8vh auto 1.5rem;
            text-align: center;
        }

        .login-brand {
            color: var(--cyan);
            font-size: 3.5rem;
            text-shadow: 0 0 25px rgba(0, 217, 255, .5);
        }

        .login-wrapper h1 {
            color: var(--cyan);
            font-size: 2.3rem;
            margin: .4rem 0;
        }

        .login-wrapper p {
            color: var(--muted);
        }

        .logged-user {
            padding: .7rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: rgba(13, 23, 40, .7);
        }

        .logged-user small,
        .logged-user strong {
            display: block;
        }

        .logged-user small {
            color: var(--muted);
            margin-bottom: .25rem;
        }

        .logged-user strong {
            color: var(--cyan);
        }

        @media (max-width: 800px) {
            .home-notice {
                display: block;
            }

            .home-notice strong {
                display: block;
                margin-bottom: .3rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
'''


APP_PY = r'''from __future__ import annotations

from pathlib import Path

import streamlit as st

from core.auth import logout, require_login
from core.css import load_css
from core.sidebar import render_sidebar


st.set_page_config(
    page_title="Cyber Threat Research",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

load_css()

if not require_login():
    st.stop()

render_sidebar()

with st.sidebar:
    st.markdown("---")

    st.markdown(
        f"""
        <div class="logged-user">
            <small>Usuário conectado</small>
            <strong>👤 {st.session_state.get("username", "usuário")}</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("Sair da conta", use_container_width=True):
        logout()


st.markdown(
    """
    <section class="hero-home">
        <div class="hero-badge">⚡ CTR DEFENSE PLATFORM</div>
        <h1>Cyber Threat Research</h1>
        <p>
            Investigue indicadores de comprometimento, reputação,
            vazamentos e inteligência de ameaças em um único ambiente.
        </p>
    </section>
    """,
    unsafe_allow_html=True,
)

st.markdown("### Visão geral")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Módulos ativos", "4")

with col2:
    st.metric("Consultas realizadas", "—")

with col3:
    st.metric("Indicadores analisados", "—")

with col4:
    st.metric("Status da plataforma", "Online")


tools = [
    (
        "🔎",
        "Extrator de IOCs",
        "Extraia IPs, domínios, hashes e URLs de textos e arquivos.",
        "1_Extrator_IOCs.py",
    ),
    (
        "🛡️",
        "AbuseIPDB",
        "Consulte reputação, score de abuso e relatórios de IPs.",
        "2_AbuseIPDB.py",
    ),
    (
        "🧪",
        "VirusTotal",
        "Analise IPs, domínios, URLs e hashes.",
        "3_VirusTotal.py",
    ),
    (
        "🧠",
        "Threat Intelligence",
        "Organize e correlacione informações de investigação.",
        "4_Threat_Intelligence.py",
    ),
    (
        "📊",
        "Relatórios",
        "Consulte o histórico das análises realizadas.",
        "5_Relatorios.py",
    ),
    (
        "📧",
        "Vazamento de E-mail",
        "Verifique a presença de e-mails em vazamentos públicos.",
        "6_Vazamento_Email.py",
    ),
]

existing_tools = [
    tool for tool in tools
    if (Path(__file__).parent / "pages" / tool[3]).exists()
]

st.markdown("### Ferramentas disponíveis")

for start in range(0, len(existing_tools), 3):
    row = existing_tools[start:start + 3]
    columns = st.columns(3)

    for column, tool in zip(columns, row):
        icon, title, description, _filename = tool

        with column:
            st.markdown(
                f"""
                <div class="home-tool-card">
                    <div class="home-tool-icon">{icon}</div>
                    <h3>{title}</h3>
                    <p>{description}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

st.markdown(
    """
    <div class="home-notice">
        <strong>🔐 Segurança</strong>
        <span>
            As credenciais devem ficar em secrets.toml e nunca no código-fonte.
        </span>
    </div>

    <footer class="home-footer">
        © 2024–2026 Cyber Threat Research · Uso autorizado e responsável
    </footer>
    """,
    unsafe_allow_html=True,
)
'''


SECRETS_EXAMPLE = '''[auth.users.admin]
password_hash = "gere_um_hash_sha256_para_sua_senha"
role = "admin"

[api]
virustotal = ""
abuseipdb = ""
urlscan = ""
botscout = ""
'''


def update_gitignore() -> None:
    lines = []

    if GITIGNORE_FILE.exists():
        lines = GITIGNORE_FILE.read_text(encoding="utf-8").splitlines()

    required = [
        ".streamlit/secrets.toml",
        "__pycache__/",
        "*.pyc",
        "_backup_correcao/",
        "pages/_backup_pages/",
    ]

    for item in required:
        if item not in lines:
            lines.append(item)

    backup_file(GITIGNORE_FILE)
    GITIGNORE_FILE.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    print("[OK] .gitignore atualizado.")


def remove_fixed_ip_links() -> None:
    if not SIDEBAR_FILE.exists():
        print("[AVISO] core/sidebar.py não encontrado.")
        return

    backup_file(SIDEBAR_FILE)

    content = SIDEBAR_FILE.read_text(encoding="utf-8")

    # Remove URLs HTTP/HTTPS fixas usadas em links.
    content = re.sub(
        r"https?://[^\s\"'<>]+",
        "",
        content,
    )

    # Remove links Markdown/HTML quebrados que apontem para pages.
    content = re.sub(
        r'<a[^>]+href\s*=\s*["\'][^"\']*pages/[^"\']*["\'][^>]*>.*?</a>',
        "",
        content,
        flags=re.IGNORECASE | re.DOTALL,
    )

    SIDEBAR_FILE.write_text(content, encoding="utf-8")
    print("[OK] Links IP fixos removidos de core/sidebar.py.")


def move_invalid_pages() -> None:
    if not PAGES_DIR.exists():
        return

    valid_names = {
        "1_Extrator_IOCs.py",
        "2_AbuseIPDB.py",
        "3_VirusTotal.py",
        "4_Threat_Intelligence.py",
        "5_Relatorios.py",
        "6_Vazamento_Email.py",
    }

    destination = PAGES_DIR / "_backup_pages"
    moved = 0

    for item in PAGES_DIR.iterdir():
        if not item.is_file() or item.suffix != ".py":
            continue

        if item.name not in valid_names:
            destination.mkdir(exist_ok=True)
            target = destination / item.name

            if target.exists():
                target = destination / f"{item.stem}_{timestamp()}.py"

            shutil.move(str(item), str(target))
            print(f"[MOVIDO] {item} -> {target}")
            moved += 1

    if moved == 0:
        print("[OK] Nenhuma página inválida encontrada.")


def validate_project() -> bool:
    print("\n[INFO] Validando sintaxe...")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            str(CORE_DIR),
            str(PAGES_DIR),
            str(APP_FILE),
        ],
        cwd=ROOT,
        check=False,
    )

    if result.returncode == 0:
        print("[OK] Sintaxe validada com sucesso.")
        return True

    print("[ERRO] Existem erros de sintaxe no projeto.")
    return False


def main() -> int:
    print("=== Correção da Home, login e menu ===\n")

    CORE_DIR.mkdir(exist_ok=True)
    STREAMLIT_DIR.mkdir(exist_ok=True)
    PAGES_DIR.mkdir(exist_ok=True)

    write_file(AUTH_FILE, AUTH_PY)
    write_file(CSS_FILE, CSS_PY)
    write_file(APP_FILE, APP_PY)

    if not SECRETS_EXAMPLE.exists():
        write_file(SECRETS_EXAMPLE, SECRETS_EXAMPLE)
    else:
        print(f"[OK] Mantido: {SECRETS_EXAMPLE}")

    update_gitignore()
    remove_fixed_ip_links()
    move_invalid_pages()

    if not validate_project():
        return 1

    print("\n[CONCLUÍDO]")
    print("1. Gere o hash da senha:")
    print(
        "   python -c "
        "\"import hashlib; "
        "print(hashlib.sha256('SuaSenha'.encode()).hexdigest())\""
    )
    print("2. Configure .streamlit/secrets.toml.")
    print("3. Reinicie a aplicação:")
    print("   streamlit run app.py")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

