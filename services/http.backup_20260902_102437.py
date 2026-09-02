"""Cliente HTTP compartilhado com retry, timeout e resposta padronizada."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils.exceptions import (
    AuthenticationError,
    InvalidResponseError,
    NotFoundError,
    RateLimitError,
    ServiceError,
)


DEFAULT_TIMEOUT = (5, 20)
RETRYABLE_STATUS = (429, 500, 502, 503, 504)


@dataclass
class ServiceResult:
    success: bool
    data: Any = None
    error: str | None = None
    status_code: int | None = None
    source: str | None = None
    raw: Any = None
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "status_code": self.status_code,
            "source": self.source,
            "raw": self.raw,
            "cached": self.cached,
        }


def build_session(
    total_retries: int = 3,
    backoff_factor: float = 0.7,
    pool_size: int = 20,
) -> requests.Session:
    retry = Retry(
        total=total_retries,
        connect=total_retries,
        read=2,
        status=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=RETRYABLE_STATUS,
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=pool_size,
        pool_maxsize=pool_size,
    )

    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": "CTRDefense-ThreatIntel/4.0",
        }
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = build_session()


def explain_http_error(response: requests.Response, source: str) -> str:
    status = response.status_code

    try:
        payload = response.json()
        detail = (
            payload.get("error", {}).get("message")
            if isinstance(payload.get("error"), dict)
            else payload.get("message") or payload.get("error")
        )
    except (ValueError, AttributeError):
        detail = response.text[:300].strip()

    base = f"{source}: HTTP {status}"
    return f"{base} — {detail}" if detail else base


def raise_for_service_status(response: requests.Response, source: str) -> None:
    if response.status_code < 400:
        return

    message = explain_http_error(response, source)

    if response.status_code in {401, 403}:
        raise AuthenticationError(message)
    if response.status_code == 404:
        raise NotFoundError(message)
    if response.status_code == 429:
        raise RateLimitError(message)

    raise ServiceError(message)


def request_json(
    method: str,
    url: str,
    *,
    source: str,
    timeout=DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
    **kwargs,
) -> ServiceResult:
    client = session or SESSION

    try:
        response = client.request(
            method=method.upper(),
            url=url,
            timeout=timeout,
            **kwargs,
        )
        raise_for_service_status(response, source)

        try:
            payload = response.json()
        except ValueError as exc:
            raise InvalidResponseError(
                f"{source}: resposta JSON inválida."
            ) from exc

        return ServiceResult(
            success=True,
            data=payload,
            status_code=response.status_code,
            source=source,
            raw=payload,
        )

    except NotFoundError as exc:
        return ServiceResult(
            success=False,
            error=str(exc),
            status_code=404,
            source=source,
        )
    except RateLimitError as exc:
        return ServiceResult(
            success=False,
            error=str(exc),
            status_code=429,
            source=source,
        )
    except AuthenticationError as exc:
        return ServiceResult(
            success=False,
            error=str(exc),
            source=source,
        )
    except requests.Timeout:
        return ServiceResult(
            success=False,
            error=f"{source}: tempo limite excedido.",
            source=source,
        )
    except requests.RequestException as exc:
        return ServiceResult(
            success=False,
            error=f"{source}: falha de comunicação — {exc}",
            source=source,
        )
    except ServiceError as exc:
        return ServiceResult(
            success=False,
            error=str(exc),
            source=source,
        )
