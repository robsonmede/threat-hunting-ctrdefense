from __future__ import annotations

import hashlib
import hmac
from typing import Any

import streamlit as st


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _get_users() -> dict[str, Any]:
    try:
        auth_config = st.secrets.get("auth", {})
        return dict(auth_config.get("users", {}))
    except Exception:
        return {}


def authenticate(username: str, password: str) -> bool:
    username = username.strip()

    if not username or not password:
        return False

    user_data = _get_users().get(username)

    if not user_data:
        return False

    stored_hash = str(
        user_data.get("password_hash", "")
    ).strip()

    if not stored_hash:
        return False

    password_hash = _hash_password(password)

    return hmac.compare_digest(password_hash, stored_hash)


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
            <p>
                Plataforma de inteligência e análise de ameaças
            </p>
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
            username = username.strip()

            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.user_role = get_user_role(username)

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
    keys_to_remove = (
        "authenticated",
        "username",
        "user_role",
        "vt_api_key",
        "abuseipdb_api_key",
        "urlscan_api_key",
        "botscout_api_key",
    )

    for key in keys_to_remove:
        st.session_state.pop(key, None)

    st.rerun()
