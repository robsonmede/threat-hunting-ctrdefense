# services/http.py

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_TIMEOUT = 20


def get_http_session(
    *,
    retries: int = 2,
    backoff_factor: float = 0.5,
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Session:
    """
    Cria uma sessão HTTP reutilizável com retry automático.
    """

    session = requests.Session()

    retry_strategy = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(
            {
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
            }
        ),
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10,
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": "Cyber-Threat-Research/1.0",
        }
    )

    # O requests não possui timeout padrão nativo.
    # Este atributo será utilizado pelos helpers abaixo.
    session.request_timeout = timeout  # type: ignore[attr-defined]

    return session


def request_with_timeout(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Executa uma requisição utilizando o timeout configurado na sessão.
    """

    kwargs.setdefault(
        "timeout",
        getattr(session, "request_timeout", DEFAULT_TIMEOUT),
    )

    return session.request(
        method=method,
        url=url,
        **kwargs,
    )


def get(
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Executa uma requisição GET com sessão configurada.
    """

    session = get_http_session()

    return request_with_timeout(
        session,
        "GET",
        url,
        **kwargs,
    )


def post(
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Executa uma requisição POST com sessão configurada.
    """

    session = get_http_session()

    return request_with_timeout(
        session,
        "POST",
        url,
        **kwargs,
    )
