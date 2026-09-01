# services/abuseipdb.py

from __future__ import annotations

import ipaddress
from typing import Any

import requests

from services.http import get_http_session


HTTP = get_http_session()

ABUSEIPDB_CATEGORIES: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def is_valid_ip(value: str) -> bool:
    """Retorna True quando o valor é um IPv4 ou IPv6 válido."""

    if not isinstance(value, str) or not value.strip():
        return False

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _safe_json(response: requests.Response) -> dict[str, Any]:
    """Obtém JSON da resposta sem gerar erro quando o corpo está vazio."""

    try:
        payload = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return {}

    return payload if isinstance(payload, dict) else {}


def _error_message_from_payload(
    payload: dict[str, Any],
    fallback: str,
) -> str:
    """Extrai uma mensagem amigável de erro retornada pela API."""

    errors = payload.get("errors")

    if isinstance(errors, list) and errors:
        messages: list[str] = []

        for item in errors:
            if isinstance(item, dict):
                detail = item.get("detail") or item.get("message")
                if detail:
                    messages.append(str(detail))
            elif item:
                messages.append(str(item))

        if messages:
            return "; ".join(messages)

    if isinstance(errors, dict):
        detail = errors.get("detail") or errors.get("message")
        if detail:
            return str(detail)

    return fallback


def _normalize_max_age(value: Any) -> int:
    """Converte e limita o período de consulta entre 1 e 365 dias."""

    try:
        days = int(value)
    except (TypeError, ValueError):
        days = 90

    return max(1, min(365, days))


def _build_category_summary(
    reports: Any,
) -> tuple[list[tuple[str, int]], dict[str, int]]:
    """Calcula as categorias mais recorrentes nos relatórios."""

    category_counts: dict[str, int] = {}

    if not isinstance(reports, list):
        return [], category_counts

    for report in reports:
        if not isinstance(report, dict):
            continue

        categories = report.get("categories", [])

        if not isinstance(categories, list):
            continue

        for category_id in categories:
            try:
                category_id_int = int(category_id)
            except (TypeError, ValueError):
                continue

            name = ABUSEIPDB_CATEGORIES.get(
                category_id_int,
                f"Categoria {category_id_int}",
            )

            category_counts[name] = (
                category_counts.get(name, 0) + 1
            )

    top_categories = sorted(
        category_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:5]

    return top_categories, category_counts


def _risk_status(score: int) -> tuple[str, str]:
    """Retorna o texto e a classe CSS correspondentes ao score."""

    if score >= 75:
        return "🚨 ALTO RISCO", "status-danger"

    if score >= 50:
        return "🟡 RISCO MODERADO", "status-warn"

    if score >= 25:
        return "🟠 RISCO BAIXO", "status-warn"

    return "✅ BAIXO RISCO", "status-safe"


def check_abuseipdb(
    api_key: str | None,
    ip_address: str,
    max_age_days: int = 90,
) -> dict[str, Any]:
    """
    Consulta a reputação de um endereço IP no AbuseIPDB.

    A assinatura preserva a compatibilidade com chamadas existentes:

        check_abuseipdb(api_key, ip_address, max_age_days)

    Retorna um dicionário com a chave ``error`` em caso de falha.
    """

    ip_address = (
        ip_address.strip()
        if isinstance(ip_address, str)
        else ""
    )

    if not is_valid_ip(ip_address):
        return {
            "error": "Endereço IP inválido.",
        }

    if not isinstance(api_key, str) or not api_key.strip():
        return {
            "error": (
                "API Key do AbuseIPDB não configurada. "
                "Verifique o sidebar ou o secrets.toml."
            ),
        }

    max_age_days = _normalize_max_age(max_age_days)

    endpoint = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": api_key.strip(),
        "User-Agent": "ThreatIntelStreamlit/3.9",
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "verbose": "true",
    }

    try:
        response = HTTP.get(
            endpoint,
            headers=headers,
            params=params,
            timeout=15,
        )
    except requests.exceptions.Timeout:
        return {
            "error": (
                "A consulta ao AbuseIPDB excedeu o tempo limite."
            ),
        }
    except requests.exceptions.ConnectionError:
        return {
            "error": (
                "Não foi possível estabelecer conexão "
                "com o AbuseIPDB."
            ),
        }
    except requests.exceptions.RequestException as exc:
        return {
            "error": f"Erro de comunicação com o AbuseIPDB: {exc}",
        }

    payload = _safe_json(response)

    if response.status_code == 401:
        return {
            "error": (
                "API Key do AbuseIPDB inválida ou expirada."
            ),
        }

    if response.status_code == 429:
        return {
            "error": (
                "Limite de requisições do AbuseIPDB atingido. "
                "Tente novamente mais tarde."
            ),
        }

    if response.status_code == 422:
        return {
            "error": _error_message_from_payload(
                payload,
                "IP inválido ou mal formatado.",
            ),
        }

    if response.status_code != 200:
        fallback = (
            f"Erro HTTP {response.status_code} "
            "retornado pelo AbuseIPDB."
        )

        return {
            "error": _error_message_from_payload(
                payload,
                fallback,
            ),
        }

    data = payload.get("data")

    if not isinstance(data, dict):
        return {
            "error": (
                "O AbuseIPDB retornou uma resposta "
                "sem dados válidos."
            ),
        }

    try:
        score = int(data.get("abuseConfidenceScore", 0) or 0)
    except (TypeError, ValueError):
        score = 0

    score = max(0, min(100, score))

    status, status_color = _risk_status(score)

    reports = data.get("reports", [])
    top_categories, category_counts = _build_category_summary(
        reports
    )

    return {
        "ip": ip_address,
        "status": status,
        "status_color": status_color,
        "score": f"{score}%",
        "score_raw": score,
        "reports": data.get("totalReports", 0) or 0,
        "distinct_reporters": data.get(
            "numDistinctUsers",
            0,
        ) or 0,
        "country": data.get("countryCode") or "N/D",
        "country_name": data.get("countryName") or "N/D",
        "isp": data.get("isp") or "N/D",
        "domain": data.get("domain") or "N/D",
        "hostnames": data.get("hostnames") or [],
        "usage_type": data.get("usageType") or "N/D",
        "is_whitelisted": bool(
            data.get("isWhitelisted", False)
        ),
        "is_public": bool(
            data.get("isPublic", False)
        ),
        "is_tor": bool(
            data.get("isTor", False)
        ),
        "last_reported_at": data.get(
            "lastReportedAt"
        ) or "Nunca reportado",
        "top_categories": top_categories,
        "category_counts": category_counts,
        "raw_data": data,
    }
