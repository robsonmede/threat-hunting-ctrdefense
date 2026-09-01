# services/virustotal.py
"""
Integração com a API v3 do VirusTotal.

Suporta consultas de:

- Endereços IPv4 e IPv6
- Domínios
- URLs
- Hashes MD5, SHA-1 e SHA-256

A chave da API deve ser fornecida pelo chamador. Nunca deixe chaves
reais diretamente neste arquivo ou no código-fonte versionado.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any, Literal

import requests


VirusTotalIOCType = Literal[
    "auto",
    "ip",
    "domain",
    "dominio",
    "url",
    "hash",
    "file",
    "arquivo",
]

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 30


def query_virustotal(
    api_key: str,
    ioc: str,
    ioc_type: VirusTotalIOCType = "auto",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Consulta um indicador de comprometimento no VirusTotal.

    Parâmetros:
        api_key:
            Chave da API do VirusTotal.

        ioc:
            IP, domínio, URL ou hash a ser consultado.

        ioc_type:
            Tipo do indicador. Aceita:
            auto, ip, domain, url, hash, file.

        timeout:
            Tempo máximo da requisição, em segundos.

    Retorno em caso de sucesso:

        {
            "success": True,
            "status_code": 200,
            "ioc": "...",
            "ioc_type": "ip",
            "endpoint": "...",
            "data": {...},
            "attributes": {...},
            "stats": {...},
            "reputation": 10
        }

    Retorno em caso de erro:

        {
            "success": False,
            "status_code": 401,
            "error": "Mensagem de erro"
        }
    """

    if not isinstance(api_key, str) or not api_key.strip():
        return _error_result(
            "Chave da API do VirusTotal não configurada."
        )

    if not isinstance(ioc, str) or not ioc.strip():
        return _error_result(
            "O indicador de comprometimento não foi informado."
        )

    ioc = ioc.strip()
    normalized_type = _normalize_ioc_type(ioc_type)

    try:
        resolved_type = detect_ioc_type(ioc, normalized_type)
        endpoint = build_endpoint(ioc, resolved_type)

    except ValueError as exc:
        return _error_result(str(exc))

    headers = {
        "x-apikey": api_key.strip(),
        "Accept": "application/json",
        "User-Agent": "Cyber-Threat-Research/3.9",
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=timeout,
        )

    except requests.Timeout:
        return _error_result(
            "Tempo limite excedido ao consultar o VirusTotal."
        )

    except requests.ConnectionError:
        return _error_result(
            "Não foi possível estabelecer conexão com o VirusTotal."
        )

    except requests.RequestException as exc:
        return _error_result(
            f"Erro de comunicação com o VirusTotal: {exc}"
        )

    result = _parse_response_error(response)

    if result is not None:
        return result

    try:
        payload = response.json()

    except ValueError:
        return _error_result(
            "O VirusTotal retornou uma resposta JSON inválida.",
            status_code=response.status_code,
        )

    resource = payload.get("data", {})
    attributes = resource.get("attributes", {})

    return {
        "success": True,
        "status_code": response.status_code,
        "ioc": ioc,
        "ioc_type": resolved_type,
        "endpoint": endpoint,
        "data": payload,
        "attributes": attributes,
        "stats": attributes.get("last_analysis_stats", {}),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "meaningful_name": attributes.get("meaningful_name"),
    }


def build_endpoint(ioc: str, ioc_type: str) -> str:
    """
    Constrói o endpoint da API v3 do VirusTotal para o IOC informado.
    """

    ioc = ioc.strip()
    ioc_type = _normalize_ioc_type(ioc_type)

    if ioc_type == "ip":
        return f"{VIRUSTOTAL_API_URL}/ip_addresses/{ioc}"

    if ioc_type == "domain":
        return f"{VIRUSTOTAL_API_URL}/domains/{ioc}"

    if ioc_type == "hash":
        return f"{VIRUSTOTAL_API_URL}/files/{ioc}"

    if ioc_type == "url":
        return f"{VIRUSTOTAL_API_URL}/urls/{encode_url_id(ioc)}"

    raise ValueError(
        "Tipo de IOC inválido. Use: auto, ip, domain, url ou hash."
    )


def detect_ioc_type(ioc: str, requested_type: str = "auto") -> str:
    """
    Identifica automaticamente o tipo do IOC.

    Retorna um dos valores:
    ip, domain, url ou hash.
    """

    requested_type = _normalize_ioc_type(requested_type)

    if requested_type != "auto":
        if requested_type == "ip" and not is_valid_ip(ioc):
            raise ValueError("O valor informado não é um IP válido.")

        if requested_type == "hash" and not is_valid_hash(ioc):
            raise ValueError("O valor informado não é um hash válido.")

        if requested_type == "domain" and not is_valid_domain(ioc):
            raise ValueError("O valor informado não é um domínio válido.")

        if requested_type == "url" and not is_valid_url(ioc):
            raise ValueError("O valor informado não é uma URL válida.")

        return requested_type

    if is_valid_ip(ioc):
        return "ip"

    if is_valid_hash(ioc):
        return "hash"

    if is_valid_url(ioc):
        return "url"

    if is_valid_domain(ioc):
        return "domain"

    raise ValueError(
        "Não foi possível identificar o tipo do IOC informado."
    )


def encode_url_id(url: str) -> str:
    """
    Codifica uma URL conforme exigido pelo endpoint /urls da API v3.

    O VirusTotal utiliza Base64 URL-safe sem os caracteres '=' finais.
    """

    encoded = base64.urlsafe_b64encode(
        url.strip().encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


def is_valid_ip(value: str) -> bool:
    """Retorna True caso o valor seja um IPv4 ou IPv6 válido."""

    try:
        ipaddress.ip_address(value.strip())
        return True

    except ValueError:
        return False


def is_valid_hash(value: str) -> bool:
    """Valida hashes MD5, SHA-1 e SHA-256."""

    value = value.strip()

    return bool(
        re.fullmatch(
            r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})",
            value,
        )
    )


def is_valid_url(value: str) -> bool:
    """
    Validação básica de URL HTTP/HTTPS.

    A URL deve conter esquema e hostname.
    """

    value = value.strip()

    pattern = re.compile(
        r"^https?://"
        r"(?:[a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}"
        r"(?::\d{1,5})?"
        r"(?:[/?#][^\s]*)?$",
        re.IGNORECASE,
    )

    return bool(pattern.match(value))


def is_valid_domain(value: str) -> bool:
    """Valida um domínio sem esquema HTTP ou caminho."""

    value = value.strip().lower().rstrip(".")

    if len(value) > 253 or "://" in value or "/" in value:
        return False

    pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$",
        re.IGNORECASE,
    )

    return bool(pattern.match(value))


def _normalize_ioc_type(ioc_type: str | None) -> str:
    """Normaliza os nomes de tipos aceitos pela aplicação."""

    if not isinstance(ioc_type, str):
        return "auto"

    normalized = ioc_type.strip().lower()

    aliases = {
        "automatico": "auto",
        "automático": "auto",
        "ip_address": "ip",
        "ipv4": "ip",
        "ipv6": "ip",
        "dominio": "domain",
        "domain_name": "domain",
        "uri": "url",
        "link": "url",
        "arquivo": "hash",
        "file": "hash",
        "md5": "hash",
        "sha1": "hash",
        "sha-1": "hash",
        "sha256": "hash",
        "sha-256": "hash",
    }

    return aliases.get(normalized, normalized)


def _parse_response_error(
    response: requests.Response,
) -> dict[str, Any] | None:
    """
    Converte códigos HTTP conhecidos em respostas padronizadas.
    """

    if response.ok:
        return None

    status_code = response.status_code

    messages = {
        400: "Requisição inválida enviada ao VirusTotal.",
        401: "Chave da API do VirusTotal inválida ou não autorizada.",
        403: "Acesso negado pela API do VirusTotal.",
        404: "Indicador não encontrado no VirusTotal.",
        429: "Limite de requisições do VirusTotal excedido.",
        500: "Erro interno no servidor do VirusTotal.",
        503: "Serviço do VirusTotal temporariamente indisponível.",
    }

    default_message = messages.get(
        status_code,
        f"Erro HTTP {status_code} retornado pelo VirusTotal.",
    )

    try:
        payload = response.json()
        api_message = (
            payload.get("error", {}).get("message")
            or payload.get("data", {}).get("message")
        )

        if api_message:
            default_message = str(api_message)

    except (ValueError, AttributeError, TypeError):
        pass

    return _error_result(
        default_message,
        status_code=status_code,
    )


def _error_result(
    message: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Cria uma resposta de erro padronizada."""

    result: dict[str, Any] = {
        "success": False,
        "error": message,
    }

    if status_code is not None:
        result["status_code"] = status_code

    return result


__all__ = [
    "query_virustotal",
    "build_endpoint",
    "detect_ioc_type",
    "encode_url_id",
    "is_valid_ip",
    "is_valid_hash",
    "is_valid_url",
    "is_valid_domain",
]

