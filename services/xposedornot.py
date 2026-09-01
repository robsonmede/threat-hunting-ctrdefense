# services/xposedornot.py

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

from services.http import get_http_session
from utils.helpers import is_valid_email


HTTP = get_http_session()

XPOSEDORNOT_URL = (
    "https://api.xposedornot.com/v1/check-email/"
)

USER_AGENT = "CyberThreatResearch/3.9"


def _safe_json(response: requests.Response) -> dict[str, Any] | list[Any] | None:
    """
    Tenta interpretar a resposta como JSON sem lançar exceção.

    A API pode retornar corpo vazio, HTML ou texto simples mesmo em
    respostas HTTP aparentemente válidas.
    """

    content = response.text or ""

    if not content.strip():
        return None

    content_type = (
        response.headers.get("Content-Type", "").lower()
    )

    # O endpoint normalmente retorna JSON, mas não dependemos apenas
    # do Content-Type, pois alguns servidores o configuram incorretamente.
    try:
        data = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return None

    if isinstance(data, (dict, list)):
        return data

    return None


def _to_int(value: Any) -> int:
    """Converte valores numéricos da API com segurança."""

    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _normalize_data_classes(value: Any) -> list[str]:
    """Normaliza as categorias de dados expostos."""

    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, (list, tuple, set)):
        return [
            str(item)
            for item in value
            if item is not None
        ][:20]

    return []


def _extract_breaches(
    data: dict[str, Any],
) -> list[Any]:
    """
    Extrai a lista de vazamentos considerando os formatos mais comuns
    retornados pelo XposedOrNot.
    """

    possible_keys = (
        "breaches",
        "Breaches",
        "exposed_breaches",
        "ExposedBreaches",
        "data",
    )

    breaches: Any = []

    for key in possible_keys:
        if key in data:
            breaches = data[key]
            break

    if isinstance(breaches, dict):
        for key in possible_keys:
            nested = breaches.get(key)
            if isinstance(nested, list):
                breaches = nested
                break
        else:
            breaches = []

    if not isinstance(breaches, list):
        return []

    return breaches


def _normalize_breach(breach: Any) -> dict[str, Any]:
    """Converte um vazamento para um formato uniforme."""

    if isinstance(breach, str):
        return {
            "name": breach,
            "title": breach,
            "date": "N/D",
            "records_exposed": 0,
            "data_classes": [],
            "description": "",
        }

    if not isinstance(breach, dict):
        return {
            "name": "N/D",
            "title": "N/D",
            "date": "N/D",
            "records_exposed": 0,
            "data_classes": [],
            "description": "",
        }

    records = _to_int(
        breach.get("PwnCount")
        or breach.get("pwn_count")
        or breach.get("records_exposed")
        or breach.get("RecordsExposed")
    )

    data_classes = _normalize_data_classes(
        breach.get("DataClasses")
        or breach.get("data_classes")
        or breach.get("dataClasses")
    )

    description = (
        breach.get("Description")
        or breach.get("description")
        or ""
    )

    return {
        "name": (
            breach.get("Name")
            or breach.get("name")
            or "N/D"
        ),
        "title": (
            breach.get("Title")
            or breach.get("title")
            or breach.get("Name")
            or breach.get("name")
            or "N/D"
        ),
        "date": (
            breach.get("BreachDate")
            or breach.get("breach_date")
            or breach.get("date")
            or "N/D"
        ),
        "records_exposed": records,
        "data_classes": data_classes,
        "description": str(description)[:500],
    }


def query_xposedornot(
    email: str,
    api_key: str | None = None,
) -> dict[str, Any]:
    """
    Consulta vazamentos associados a um endereço de e-mail.

    Retorna sempre um dicionário. Em caso de falha, o resultado terá
    a chave ``error``.
    """

    email = (email or "").strip().lower()

    if not is_valid_email(email):
        return {
            "error": "E-mail inválido",
            "email": email,
        }

    encoded_email = quote(email, safe="")
    url = f"{XPOSEDORNOT_URL}{encoded_email}"

    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }

    if api_key and api_key.strip():
        headers["x-api-key"] = api_key.strip()

    try:
        response = HTTP.get(
            url,
            headers=headers,
            timeout=15,
        )

    except requests.exceptions.Timeout:
        return {
            "error": "Timeout na consulta ao XposedOrNot",
            "email": email,
        }

    except requests.exceptions.RequestException as exc:
        return {
            "error": f"Erro de conexão com o XposedOrNot: {exc}",
            "email": email,
        }

    status_code = response.status_code

    if status_code in (204, 404):
        return {
            "email": email,
            "status": "SEGURO",
            "breaches_found": 0,
            "message": "Nenhum vazamento conhecido foi encontrado.",
            "breach_list": [],
            "total_records": 0,
            "raw_data": {},
        }

    if status_code in (401, 403):
        return {
            "error": (
                "Chave da API inválida, ausente ou não autorizada"
            ),
            "email": email,
        }

    if status_code == 429:
        return {
            "error": (
                "Limite de requisições excedido pelo XposedOrNot"
            ),
            "email": email,
        }

    if status_code >= 500:
        return {
            "error": (
                f"Serviço XposedOrNot indisponível "
                f"(HTTP {status_code})"
            ),
            "email": email,
        }

    if status_code != 200:
        return {
            "error": (
                f"Erro HTTP {status_code} "
                "na consulta ao XposedOrNot"
            ),
            "email": email,
        }

    data = _safe_json(response)

    if data is None:
        return {
            "error": (
                "O XposedOrNot retornou uma resposta vazia "
                "ou não-JSON"
            ),
            "email": email,
            "http_status": status_code,
        }

    if isinstance(data, list):
        data = {"breaches": data}

    breaches = _extract_breaches(data)

    breach_list = [
        _normalize_breach(breach)
        for breach in breaches[:20]
    ]

    total_records = sum(
        item["records_exposed"]
        for item in breach_list
    )

    count = len(breaches)

    if count >= 5:
        risk_status = "ALTO RISCO"
    elif count >= 2:
        risk_status = "RISCO MODERADO"
    elif count == 1:
        risk_status = "RISCO BAIXO"
    else:
        risk_status = "SEGURO"

    return {
        "email": email,
        "status": risk_status,
        "breaches_found": count,
        "message": (
            f"{count} vazamento(s) encontrado(s)."
            if count
            else "Nenhum vazamento conhecido foi encontrado."
        ),
        "breach_list": breach_list,
        "total_records": total_records,
        "raw_data": data,
    }
