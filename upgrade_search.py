#!/usr/bin/env python3
"""
Migração de robustez das consultas do threat-intel-streamlit.

Execute na raiz do projeto:

    python upgrade_searches.py

Opções:

    python upgrade_searches.py --dry-run
    python upgrade_searches.py --root /caminho/threat-intel-streamlit
    python upgrade_searches.py --no-tests

O script é idempotente e cria backup antes de alterar arquivos existentes.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent


MARKER = "# AUTO-UPGRADE-SEARCHES-V1"
CREATED_FILES = [
    "utils/exceptions.py",
    "utils/validators.py",
    "utils/search.py",
    "services/http.py",
    "tests/test_validators.py",
]

VALIDATORS_CONTENT = r'''
"""Validação, normalização e extração segura de indicadores."""

from __future__ import annotations

import base64
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from typing import Iterable


EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\.?$",
    re.IGNORECASE,
)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class IOCCollection:
    ips: list[str]
    domains: list[str]
    urls: list[str]
    md5: list[str]
    sha1: list[str]
    sha256: list[str]
    emails: list[str]
    cves: list[str]

    @property
    def hashes(self) -> list[str]:
        return self.md5 + self.sha1 + self.sha256

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "ips": self.ips,
            "domains": self.domains,
            "urls": self.urls,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "emails": self.emails,
            "cves": self.cves,
        }


def normalize_text(value: str | None) -> str:
    return (value or "").strip()


def refang(value: str | None) -> str:
    """Normaliza IOCs deliberadamente ofuscados em relatórios de segurança."""
    text = normalize_text(value)

    replacements = (
        (r"(?i)\bhxxps\b", "https"),
        (r"(?i)\bhxxp\b", "http"),
        (r"\[\s*:\s*\]", ":"),
        (r"\(\s*:\s*\)", ":"),
        (r"\{\s*:\s*\}", ":"),
        (r"\[\s*\.\s*\]", "."),
        (r"\(\s*\.\s*\)", "."),
        (r"\{\s*\.\s*\}", "."),
        (r"\[\s*@\s*\]", "@"),
        (r"\(\s*@\s*\)", "@"),
    )

    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text)

    return text


def normalize_ip(value: str | None) -> str:
    text = normalize_text(value)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def is_valid_ip(value: str | None, public_only: bool = False) -> bool:
    try:
        ip = ipaddress.ip_address(normalize_text(value))
    except ValueError:
        return False

    if not public_only:
        return True

    return not any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def is_valid_ipv4(value: str | None, public_only: bool = False) -> bool:
    try:
        ip = ipaddress.ip_address(normalize_text(value))
    except ValueError:
        return False

    if ip.version != 4:
        return False

    return is_valid_ip(str(ip), public_only=public_only)


def normalize_domain(value: str | None) -> str:
    text = refang(value).lower().strip().rstrip(".")

    if "://" in text:
        parsed = urllib.parse.urlsplit(text)
        text = parsed.hostname or ""

    text = text.split("/")[0].split(":")[0].strip().rstrip(".")

    if not text:
        return ""

    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def is_valid_domain(value: str | None) -> bool:
    domain = normalize_domain(value)
    if not domain or is_valid_ip(domain):
        return False
    return bool(DOMAIN_PATTERN.fullmatch(domain))


def normalize_url(value: str | None, add_scheme: bool = False) -> str:
    text = refang(value).strip().rstrip(".,;)>]}\"'")

    if add_scheme and text and "://" not in text:
        text = "https://" + text

    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    if not parsed.hostname:
        return ""
    if not (is_valid_domain(parsed.hostname) or is_valid_ip(parsed.hostname)):
        return ""

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()

    try:
        port = parsed.port
    except ValueError:
        return ""

    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    if port:
        netloc += f":{port}"

    path = parsed.path or ""
    return urllib.parse.urlunsplit(
        (scheme, netloc, path, parsed.query, parsed.fragment)
    )


def is_valid_url(value: str | None) -> bool:
    return bool(normalize_url(value))


def normalize_email(value: str | None) -> str:
    return refang(value).strip().lower().rstrip(".,;:)>]}\"'")


def is_valid_email(value: str | None) -> bool:
    return bool(EMAIL_PATTERN.fullmatch(normalize_email(value)))


def detect_hash_type(value: str | None) -> str | None:
    text = normalize_text(value)
    if MD5_PATTERN.fullmatch(text):
        return "MD5"
    if SHA1_PATTERN.fullmatch(text):
        return "SHA1"
    if SHA256_PATTERN.fullmatch(text):
        return "SHA256"
    return None


def is_valid_hash(value: str | None) -> bool:
    return detect_hash_type(value) is not None


def normalize_cve(value: str | None) -> str:
    return normalize_text(value).upper()


def is_valid_cve(value: str | None) -> bool:
    return bool(CVE_PATTERN.fullmatch(normalize_cve(value)))


def detect_ioc_type(value: str | None) -> str:
    raw = refang(value).strip()

    if is_valid_ip(raw):
        return "IP"

    hash_type = detect_hash_type(raw)
    if hash_type:
        return hash_type

    if is_valid_email(raw):
        return "EMAIL"

    if is_valid_cve(raw):
        return "CVE"

    if is_valid_url(raw):
        return "URL"

    if is_valid_domain(raw):
        return "DOMAIN"

    return "TERM"


def vt_url_id(value: str) -> str:
    normalized = normalize_url(value)
    target = normalized or normalize_text(value)
    return base64.urlsafe_b64encode(target.encode("utf-8")).decode("ascii").rstrip("=")


def _unique(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value})


def extract_iocs(text: str | None) -> IOCCollection:
    normalized = refang(text)

    url_candidates = re.findall(
        r"(?i)\bhttps?://[^\s<>{}\[\]\"']+",
        normalized,
    )

    urls = []
    for candidate in url_candidates:
        url = normalize_url(candidate)
        if url:
            urls.append(url)

    text_without_urls = normalized
    for candidate in url_candidates:
        text_without_urls = text_without_urls.replace(candidate, " ")

    ip_candidates = re.findall(
        r"(?<![A-Fa-f0-9:.])"
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r"(?![A-Fa-f0-9:.])",
        normalized,
    )
    ips = [normalize_ip(candidate) for candidate in ip_candidates]
    ips = [candidate for candidate in ips if candidate]

    email_candidates = re.findall(
        r"(?i)(?<![\w.+-])"
        r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"(?:[A-Z0-9-]+\.)+[A-Z]{2,63}"
        r"(?![\w.-])",
        normalized,
    )
    emails = [
        normalize_email(candidate)
        for candidate in email_candidates
        if is_valid_email(candidate)
    ]

    cves = [
        normalize_cve(candidate)
        for candidate in re.findall(
            r"(?i)\bCVE-\d{4}-\d{4,7}\b",
            normalized,
        )
    ]

    sha256 = re.findall(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", normalized)
    sha1 = re.findall(r"(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])", normalized)
    md5 = re.findall(r"(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])", normalized)

    domain_candidates = re.findall(
        r"(?i)(?<![@\w-])"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}"
        r"(?![\w-])",
        text_without_urls,
    )

    email_domains = {email.rsplit("@", 1)[-1] for email in emails}
    domains = []

    for candidate in domain_candidates:
        domain = normalize_domain(candidate)
        if is_valid_domain(domain) and domain not in email_domains:
            domains.append(domain)

    return IOCCollection(
        ips=_unique(ips),
        domains=_unique(domains),
        urls=_unique(urls),
        md5=_unique(value.lower() for value in md5),
        sha1=_unique(value.lower() for value in sha1),
        sha256=_unique(value.lower() for value in sha256),
        emails=_unique(emails),
        cves=_unique(cves),
    )
'''

EXCEPTIONS_CONTENT = '''
"""Exceções compartilhadas pelas integrações externas."""


class ThreatIntelError(Exception):
    """Erro-base da aplicação."""


class ValidationError(ThreatIntelError):
    """Entrada inválida."""


class ServiceError(ThreatIntelError):
    """Falha em serviço externo."""


class AuthenticationError(ServiceError):
    """Credencial ausente ou inválida."""


class NotFoundError(ServiceError):
    """Indicador não encontrado."""


class RateLimitError(ServiceError):
    """Cota ou limite temporário atingido."""


class InvalidResponseError(ServiceError):
    """Resposta externa inválida ou inesperada."""
'''

HTTP_CONTENT = '''
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
'''

SEARCH_CONTENT = '''
"""Execução segura e paralela de consultas."""

from __future__ import annotations

import concurrent.futures
import logging
from dataclasses import dataclass
from typing import Any, Callable


LOGGER = logging.getLogger(__name__)


@dataclass
class SearchOutcome:
    source: str
    success: bool
    data: Any = None
    error: str | None = None
    skipped: bool = False

    def to_dict(self) -> dict[str, Any]:
        if self.skipped:
            return {
                "configured": False,
                "message": self.error or "Fonte não configurada.",
            }
        if not self.success:
            return {"error": self.error or "Falha desconhecida."}
        return self.data


def execute_safe(
    source: str,
    callback: Callable,
    *args,
    **kwargs,
) -> SearchOutcome:
    try:
        result = callback(*args, **kwargs)

        if isinstance(result, dict) and result.get("error"):
            return SearchOutcome(
                source=source,
                success=False,
                data=result,
                error=str(result["error"]),
            )

        return SearchOutcome(
            source=source,
            success=True,
            data=result,
        )
    except Exception as exc:
        LOGGER.exception("Falha na consulta da fonte %s", source)
        return SearchOutcome(
            source=source,
            success=False,
            error=str(exc),
        )


def execute_parallel(
    tasks: dict[str, tuple[Callable, tuple, dict]],
    *,
    max_workers: int = 8,
    timeout: int = 60,
) -> dict[str, Any]:
    """
    tasks = {
        "VirusTotal": (funcao, (arg1, arg2), {"opcao": True}),
    }
    """
    if not tasks:
        return {}

    results: dict[str, Any] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(max_workers, len(tasks))
    ) as executor:
        futures = {
            executor.submit(execute_safe, source, callback, *args, **kwargs): source
            for source, (callback, args, kwargs) in tasks.items()
        }

        try:
            iterator = concurrent.futures.as_completed(
                futures,
                timeout=timeout,
            )
            for future in iterator:
                source = futures[future]
                try:
                    outcome = future.result()
                    results[source] = outcome.to_dict()
                except Exception as exc:
                    results[source] = {"error": str(exc)}
        except concurrent.futures.TimeoutError:
            for future, source in futures.items():
                if not future.done():
                    future.cancel()
                    results[source] = {
                        "error": f"Consulta excedeu {timeout}s."
                    }

    return results
'''

TESTS_CONTENT = r'''
from utils.validators import (
    detect_ioc_type,
    extract_iocs,
    is_valid_domain,
    is_valid_email,
    is_valid_ip,
    is_valid_url,
    refang,
)


def test_refang():
    assert refang("hxxps[:]//example[.]com/a") == "https://example.com/a"


def test_ip_validation_rejects_invalid_octet():
    assert is_valid_ip("8.8.8.8")
    assert not is_valid_ip("999.8.8.8")


def test_domain_validation():
    assert is_valid_domain("example.com")
    assert not is_valid_domain("sem-tld")


def test_url_validation():
    assert is_valid_url("https://example.com/login")
    assert not is_valid_url("javascript:alert(1)")


def test_email_validation():
    assert is_valid_email("analista@example.com")
    assert not is_valid_email("email-invalido")


def test_type_detection():
    assert detect_ioc_type("8.8.8.8") == "IP"
    assert detect_ioc_type("example.com") == "DOMAIN"
    assert detect_ioc_type("CVE-2024-21410") == "CVE"


def test_extract_defanged_iocs():
    result = extract_iocs(
        """
        hxxps[:]//evil[.]example/path
        8[.]8[.]8[.]8
        analyst[@]example[.]com
        CVE-2024-21410
        d41d8cd98f00b204e9800998ecf8427e
        """
    )

    assert "https://evil.example/path" in result.urls
    assert "8.8.8.8" in result.ips
    assert "analyst@example.com" in result.emails
    assert "CVE-2024-21410" in result.cves
    assert "d41d8cd98f00b204e9800998ecf8427e" in result.md5
'''

UTILS_INIT_CONTENT = '''
"""Utilitários compartilhados pela aplicação."""

from utils.validators import (
    IOCCollection,
    detect_hash_type,
    detect_ioc_type,
    extract_iocs,
    is_valid_cve,
    is_valid_domain,
    is_valid_email,
    is_valid_ip,
    is_valid_ipv4,
    is_valid_url,
    normalize_domain,
    normalize_email,
    normalize_url,
    refang,
    vt_url_id,
)

__all__ = [
    "IOCCollection",
    "detect_hash_type",
    "detect_ioc_type",
    "extract_iocs",
    "is_valid_cve",
    "is_valid_domain",
    "is_valid_email",
    "is_valid_ip",
    "is_valid_ipv4",
    "is_valid_url",
    "normalize_domain",
    "normalize_email",
    "normalize_url",
    "refang",
    "vt_url_id",
]
'''

SERVICES_INIT_CONTENT = '''
"""Integrações externas da aplicação."""
'''

APP_IMPORT_BLOCK = '''
# AUTO-UPGRADE-SEARCHES-V1
from utils.validators import (
    detect_hash_type as validated_hash_type,
    detect_ioc_type as validated_ioc_type,
    extract_iocs as extract_iocs_complete,
    is_valid_cve,
    is_valid_domain,
    is_valid_email,
    is_valid_ip,
    is_valid_url,
    normalize_domain,
    normalize_email,
    normalize_url,
    refang,
)
'''

APP_HELPERS_BLOCK = r'''

# AUTO-UPGRADE-SEARCHES-V1-HELPERS
def detect_osint_query_type_v2(value):
    """Detector completo, incluindo IPv6 e IOCs normalizados."""
    return validated_ioc_type(refang(value))


@st.cache_data(ttl=86400, show_spinner=False)
def check_xposedornot_analytics_cached(email):
    """Cache de 24 horas para preservar a cota e evitar consultas repetidas."""
    return check_xposedornot_analytics(normalize_email(email))


def build_complete_ioc_rows(text):
    """
    Extrai IOCs tradicionais e defangados.

    Compatibilidade:
    - Mantém os quatro grupos usados pela tela antiga.
    - Disponibiliza SHA1, domínios, e-mails e CVEs para novas telas.
    """
    result = extract_iocs_complete(text)
    return result


def validate_osint_input(value, kind):
    value = refang(value).strip()

    validators = {
        "IP": (is_valid_ip, "Informe um endereço IP válido."),
        "DOMAIN": (is_valid_domain, "Informe um domínio válido."),
        "URL": (is_valid_url, "Informe uma URL HTTP/HTTPS válida."),
        "EMAIL": (is_valid_email, "Informe um e-mail válido."),
        "CVE": (is_valid_cve, "Informe uma CVE válida."),
    }

    validator = validators.get(kind)
    if validator and not validator[0](value):
        return False, validator[1]

    if kind in {"MD5", "SHA1", "SHA256"}:
        detected = validated_hash_type(value)
        if detected != kind:
            return False, f"O valor não corresponde a um hash {kind} válido."

    return True, None
'''


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


class Migrator:
    def __init__(self, root: Path, dry_run: bool = False):
        self.root = root.resolve()
        self.dry_run = dry_run
        self.backup_root = self.root / ".upgrade_backups" / timestamp()
        self.changed: list[Path] = []
        self.created: list[Path] = []
        self.warnings: list[str] = []

    def log(self, message: str) -> None:
        print(message)

    def ensure_project(self) -> None:
        app = self.root / "app.py"
        if not app.exists():
            raise FileNotFoundError(
                f"app.py não encontrado em: {self.root}"
            )

    def backup(self, path: Path) -> None:
        if not path.exists() or self.dry_run:
            return

        relative = path.relative_to(self.root)
        destination = self.backup_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)

    def write(self, relative: str, content: str, overwrite: bool = True) -> None:
        path = self.root / relative
        normalized = dedent(content).lstrip()

        if path.exists():
            current = path.read_text(encoding="utf-8")
            if current == normalized:
                self.log(f"[OK] Sem alteração: {relative}")
                return
            if not overwrite:
                self.log(f"[PULAR] Arquivo existente preservado: {relative}")
                return
            self.backup(path)
            self.changed.append(path)
        else:
            self.created.append(path)

        self.log(f"[GRAVAR] {relative}")
        if not self.dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(normalized, encoding="utf-8")

    def patch_text(
        self,
        relative: str,
        old: str,
        new: str,
        description: str,
        required: bool = False,
    ) -> bool:
        path = self.root / relative
        if not path.exists():
            if required:
                self.warnings.append(f"{description}: {relative} não encontrado.")
            return False

        content = path.read_text(encoding="utf-8")

        if new in content:
            self.log(f"[OK] Já aplicado: {description}")
            return True

        if old not in content:
            message = f"{description}: padrão não encontrado."
            self.warnings.append(message)
            self.log(f"[AVISO] {message}")
            return False

        updated = content.replace(old, new, 1)
        self.backup(path)
        self.changed.append(path)

        self.log(f"[PATCH] {description}")
        if not self.dry_run:
            path.write_text(updated, encoding="utf-8")
        return True

    def insert_after_imports(self) -> None:
        path = self.root / "app.py"
        content = path.read_text(encoding="utf-8")

        if MARKER in content:
            self.log("[OK] Imports de validação já instalados.")
            return

        anchor = "from urllib3.util.retry import Retry\n"
        if anchor not in content:
            self.warnings.append(
                "Não foi possível localizar o bloco de imports do app.py."
            )
            return

        self.backup(path)
        updated = content.replace(
            anchor,
            anchor + "\n" + dedent(APP_IMPORT_BLOCK).lstrip(),
            1,
        )

        self.changed.append(path)
        self.log("[PATCH] Imports dos validadores no app.py")
        if not self.dry_run:
            path.write_text(updated, encoding="utf-8")

    def append_helpers(self) -> None:
        path = self.root / "app.py"
        content = path.read_text(encoding="utf-8")

        helper_marker = "# AUTO-UPGRADE-SEARCHES-V1-HELPERS"
        if helper_marker in content:
            self.log("[OK] Helpers de busca já instalados.")
            return

        anchor = "# -----------------------------------------------------------------------------\n# 7. NAVEGAÇÃO POR ABAS OPERACIONAIS"
        if anchor not in content:
            self.warnings.append(
                "Não foi possível inserir os helpers antes das abas."
            )
            return

        updated = content.replace(
            anchor,
            dedent(APP_HELPERS_BLOCK).rstrip() + "\n\n" + anchor,
            1,
        )

        self.backup(path)
        self.changed.append(path)
        self.log("[PATCH] Helpers de busca e validação no app.py")
        if not self.dry_run:
            path.write_text(updated, encoding="utf-8")

    def patch_app(self) -> None:
        self.insert_after_imports()
        self.append_helpers()

        # Usa a sessão compartilhada em vez de abrir conexões isoladas.
        direct_request_replacements = [
            (
                'response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=15)',
                'response = HTTP.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=15)',
                "urlscan submit usa sessão HTTP compartilhada",
            ),
            (
                'response = requests.get("https://urlscan.io/api/v1/search/", headers=headers, params={"q": query, "size": size}, timeout=15)',
                'response = HTTP.get("https://urlscan.io/api/v1/search/", headers=headers, params={"q": query, "size": size}, timeout=15)',
                "urlscan search usa sessão HTTP compartilhada",
            ),
            (
                "response = requests.get(url, headers=headers, timeout=15)",
                "response = HTTP.get(url, headers=headers, timeout=15)",
                "resultado urlscan usa sessão HTTP compartilhada",
            ),
            (
                'res = requests.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": email}, timeout=10)',
                'res = HTTP.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": email}, timeout=10)',
                "XposedOrNot usa sessão HTTP compartilhada",
            ),
            (
                'shot = requests.get(summary["screenshot_url"], headers=shot_headers, timeout=15)',
                'shot = HTTP.get(summary["screenshot_url"], headers=shot_headers, timeout=15)',
                "screenshot urlscan usa sessão compartilhada",
            ),
        ]

        for old, new, description in direct_request_replacements:
            self.patch_text("app.py", old, new, description)

        # Substitui o detector antigo pelo detector robusto sem remover compatibilidade.
        old_detector_start = '''def detect_osint_query_type(value):
    value = (value or "").strip()
'''
        new_detector_start = '''def detect_osint_query_type(value):
    # Detector robusto compartilhado: suporta IPv4, IPv6, IDN e IOCs defangados.
    detected = validated_ioc_type(refang(value))
    if detected != "TERM":
        return detected

    value = (value or "").strip()
'''
        self.patch_text(
            "app.py",
            old_detector_start,
            new_detector_start,
            "detecção robusta de tipo de IOC",
        )

        # Extrator completo mantendo a assinatura esperada pela tela legada.
        old_extract = r'''    def extract_iocs(text):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        ips = sorted({ip for ip in re.findall(ip_pattern, text) if is_valid_ipv4(ip)})
        urls = sorted(set(re.findall(url_pattern, text)))
        md5s = sorted(set(re.findall(md5_pattern, text)))
        sha256s = sorted(set(re.findall(sha256_pattern, text)))
        return ips, urls, md5s, sha256s
'''
        new_extract = '''    def extract_iocs(text):
        extracted = extract_iocs_complete(text)
        st.session_state["last_extracted_iocs"] = extracted.as_dict()
        return (
            extracted.ips,
            extracted.urls,
            extracted.md5,
            extracted.sha256,
        )
'''
        self.patch_text(
            "app.py",
            old_extract,
            new_extract,
            "extração de IOCs defangados e validação completa",
        )

        # Inclui SHA1 na triagem mesmo que a tela antiga tenha quatro métricas.
        self.patch_text(
            "app.py",
            "        all_hashes = md5s + sha256s\n",
            '''        extracted_extra = st.session_state.get("last_extracted_iocs", {})
        sha1s = extracted_extra.get("sha1", [])
        all_hashes = md5s + sha1s + sha256s
''',
            "inclusão de SHA1 na triagem",
        )

        # Exibe tipos adicionais encontrados.
        old_divider = '''        c4.metric("Hashes SHA256", len(sha256s))
        st.divider()
'''
        new_divider = '''        c4.metric("Hashes SHA256", len(sha256s))

        extra_iocs = st.session_state.get("last_extracted_iocs", {})
        x1, x2, x3, x4 = st.columns(4)
        x1.metric("Domínios", len(extra_iocs.get("domains", [])))
        x2.metric("Hashes SHA1", len(extra_iocs.get("sha1", [])))
        x3.metric("E-mails", len(extra_iocs.get("emails", [])))
        x4.metric("CVEs", len(extra_iocs.get("cves", [])))

        if extra_iocs.get("domains"):
            st.markdown("**Domínios extraídos:**")
            st.code("\\n".join(extra_iocs["domains"]))

        if extra_iocs.get("emails"):
            st.markdown("**E-mails extraídos:**")
            st.code("\\n".join(extra_iocs["emails"]))

        if extra_iocs.get("cves"):
            st.markdown("**CVEs extraídas:**")
            render_cve_table(extra_iocs["cves"])

        st.divider()
'''
        self.patch_text(
            "app.py",
            old_divider,
            new_divider,
            "exibição dos novos tipos de IOC",
        )

        # Cache de 24 horas para vazamentos.
        self.patch_text(
            "app.py",
            "                res = check_xposedornot_analytics(target_email)\n",
            "                res = check_xposedornot_analytics_cached(target_email)\n",
            "cache da busca de vazamentos",
        )

        self.patch_text(
            "app.py",
            'futures["XposedOrNot"] = executor.submit(check_xposedornot_analytics, raw)',
            'futures["XposedOrNot"] = executor.submit(check_xposedornot_analytics_cached, raw)',
            "cache do XposedOrNot no OSINT",
        )

        # Corrige modo manual de hash.
        old_mode_map = '''            mode_map = {"Automático": auto_kind, "IP": "IP", "Domínio": "DOMAIN", "URL": "URL",
                        "Hash": "SHA256" if re.fullmatch(r"[0-9a-fA-F]{64}", raw) else auto_kind,
                        "E-mail": "EMAIL", "CVE/Termo": "CVE"}
'''
        new_mode_map = '''            forced_hash_type = validated_hash_type(raw)
            mode_map = {
                "Automático": auto_kind,
                "IP": "IP",
                "Domínio": "DOMAIN",
                "URL": "URL",
                "Hash": forced_hash_type or "INVALID_HASH",
                "E-mail": "EMAIL",
                "CVE/Termo": "CVE" if is_valid_cve(raw) else "TERM",
            }
'''
        self.patch_text(
            "app.py",
            old_mode_map,
            new_mode_map,
            "detecção correta de MD5, SHA1 e SHA256 no modo manual",
        )

        old_ip_validation = '''            if kind == "IP" and not is_valid_ipv4(raw):
                st.error("Informe um IPv4 válido.")
            else:
'''
        new_ip_validation = '''            input_ok, input_error = validate_osint_input(raw, kind)
            if kind == "INVALID_HASH":
                st.error("Informe um hash MD5, SHA1 ou SHA256 válido.")
            elif not input_ok:
                st.error(input_error)
            else:
                raw = refang(raw)
'''
        self.patch_text(
            "app.py",
            old_ip_validation,
            new_ip_validation,
            "validação completa antes da consulta OSINT",
        )

        # Implementa a consulta direta de CVE na NVD.
        old_cve_area = '''                        if kind == "EMAIL":
                            futures["BotScout"] = executor.submit(check_botscout_email, raw)
                            futures["XposedOrNot"] = executor.submit(check_xposedornot_analytics_cached, raw)
                        unified = {}
'''
        new_cve_area = '''                        if kind == "EMAIL":
                            futures["BotScout"] = executor.submit(check_botscout_email, raw)
                            futures["XposedOrNot"] = executor.submit(check_xposedornot_analytics_cached, raw)
                        if kind == "CVE":
                            futures["NVD"] = executor.submit(get_cve_details, raw)
                        unified = {}
'''
        self.patch_text(
            "app.py",
            old_cve_area,
            new_cve_area,
            "consulta direta de CVE na NVD",
        )

        # Renderiza o resultado da NVD no relatório consolidado.
        nvd_anchor = '''    bs = results.get("BotScout", {})
'''
        nvd_render = '''    nvd = results.get("NVD", {})
    if isinstance(nvd, dict) and query_kind == "CVE":
        st.markdown("#### 🛡️ National Vulnerability Database")
        if nvd.get("error"):
            st.warning(nvd["error"])
        elif nvd.get("message"):
            st.info(nvd["message"])
        else:
            n1, n2 = st.columns(2)
            n1.metric("CVSS", nvd.get("cvss_score", "N/D"))
            n2.metric("Severidade", nvd.get("cvss_severity", "N/D"))
            st.markdown(f"**CVE:** `{nvd.get('cve_id', query_value)}`")
            st.markdown(f"**Descrição:** {nvd.get('description', 'N/D')}")
            st.markdown(f"**CWE:** {nvd.get('cwe', 'N/D')}")
            if nvd.get("link"):
                st.link_button("Abrir na NVD", nvd["link"])

    bs = results.get("BotScout", {})
'''
        self.patch_text(
            "app.py",
            nvd_anchor,
            nvd_render,
            "renderização do resultado NVD",
        )

        # Corrige promessa incorreta da Cross-Intel.
        self.patch_text(
            "app.py",
            'cross_ip = st.text_input("Insira o indicador para correlação:", placeholder="IP, domínio, URL, hash, e-mail ou CVE", key="cross_ip_input")',
            'cross_ip = st.text_input("Insira o IPv4 para correlação:", placeholder="Ex.: 8.8.8.8", key="cross_ip_input")',
            "descrição correta da entrada Cross-Intel",
        )

        self.patch_text(
            "app.py",
            'st.caption(f"Tipo detectado: **{cross_kind}** · Para relatório completo multiprotocolo, use também a aba APT-Hunter & OSINT.")',
            'st.caption(f"Tipo detectado: **{cross_kind}** · Esta tela correlaciona IPv4. Para outros IOCs, use APT-Hunter & OSINT.")',
            "orientação correta da Cross-Intel",
        )

        # Evita consulta desnecessária ao VT sem chave na Cross-Intel.
        self.patch_text(
            "app.py",
            '"vt": executor.submit(lambda: parse_vt_details(get_vt_data("ip_addresses", cross_ip))),',
            '"vt": executor.submit(lambda: parse_vt_details(get_vt_data("ip_addresses", cross_ip))) if VT_API_KEY else None,',
            "não consultar VirusTotal sem chave",
        )

        # Como Future não pode ser None, ajusta o dicionário logo depois.
        old_future_loop = '''                    results = {}
                    for key, future in futures.items():
                        try:
                            results[key] = future.result(timeout=20)
                        except Exception as exc:
                            results[key] = {"error": str(exc)}
'''
        new_future_loop = '''                    results = {}
                    for key, future in futures.items():
                        if future is None:
                            results[key] = {"error": "API Key não configurada."}
                            continue
                        try:
                            results[key] = future.result(timeout=20)
                        except concurrent.futures.TimeoutError:
                            future.cancel()
                            results[key] = {"error": "Consulta excedeu 20 segundos."}
                        except Exception as exc:
                            results[key] = {"error": str(exc)}
'''
        self.patch_text(
            "app.py",
            old_future_loop,
            new_future_loop,
            "timeout explícito e fonte não configurada na Cross-Intel",
        )

        # Não apaga autenticação ao clicar em Home.
        self.patch_text(
            "app.py",
            '''if st.button(lang["home"], key="home_button"):
    st.session_state.clear()
    st.rerun()
''',
            '''if st.button(lang["home"], key="home_button"):
    preserved = {
        key: st.session_state.get(key)
        for key in ("authenticated", "username", "language_selector")
        if key in st.session_state
    }
    st.session_state.clear()
    st.session_state.update(preserved)
    st.rerun()
''',
            "botão Home preserva autenticação",
        )

        # Corrige typo de versão.
        self.patch_text(
            "app.py",
            "Bedrohungsjäger V3.98",
            "Bedrohungsjäger V3.9",
            "correção da versão em alemão",
        )

    def update_requirements(self) -> None:
        path = self.root / "requirements.txt"
        requirements = []

        if path.exists():
            requirements = [
                line.rstrip()
                for line in path.read_text(encoding="utf-8").splitlines()
            ]

        wanted = [
            "streamlit>=1.36,<2",
            "requests>=2.32,<3",
            "urllib3>=2.2,<3",
            "pandas>=2.2,<3",
            "pytest>=8,<9",
        ]

        existing_names = {
            line.split("==")[0]
            .split(">=")[0]
            .split("<=")[0]
            .split("~=")[0]
            .strip()
            .lower()
            for line in requirements
            if line.strip() and not line.lstrip().startswith("#")
        }

        changed = False
        for requirement in wanted:
            name = (
                requirement.split("==")[0]
                .split(">=")[0]
                .split("<=")[0]
                .split("~=")[0]
                .strip()
                .lower()
            )
            if name not in existing_names:
                requirements.append(requirement)
                existing_names.add(name)
                changed = True

        if not path.exists() or changed:
            self.write(
                "requirements.txt",
                "\n".join(requirements).strip() + "\n",
            )
        else:
            self.log("[OK] requirements.txt já contém as dependências.")

    def run(self, include_tests: bool = True) -> None:
        self.ensure_project()

        self.write("utils/exceptions.py", EXCEPTIONS_CONTENT)
        self.write("utils/validators.py", VALIDATORS_CONTENT)
        self.write("utils/search.py", SEARCH_CONTENT)
        self.write("services/http.py", HTTP_CONTENT)

        utils_init = self.root / "utils/__init__.py"
        if not utils_init.exists() or not utils_init.read_text(
            encoding="utf-8"
        ).strip():
            self.write("utils/__init__.py", UTILS_INIT_CONTENT)

        services_init = self.root / "services/__init__.py"
        if not services_init.exists() or not services_init.read_text(
            encoding="utf-8"
        ).strip():
            self.write("services/__init__.py", SERVICES_INIT_CONTENT)

        if include_tests:
            self.write("tests/test_validators.py", TESTS_CONTENT)

        self.update_requirements()
        self.patch_app()

        self.log("\nMigração concluída.")

        if not self.dry_run and self.backup_root.exists():
            self.log(f"Backup: {self.backup_root}")

        if self.warnings:
            self.log("\nAvisos:")
            for warning in self.warnings:
                self.log(f"  - {warning}")

        self.log(
            dedent(
                """
                
                Próximos comandos recomendados:

                    python -m pip install -r requirements.txt
                    python -m pytest -q
                    python -m compileall app.py core services utils pages
                    streamlit run app.py
                """
            ).rstrip()
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Atualiza e fortalece as buscas do threat-intel-streamlit."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Diretório raiz do projeto. Padrão: diretório atual.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostra as alterações sem gravar arquivos.",
    )
    parser.add_argument(
        "--no-tests",
        action="store_true",
        help="Não cria os testes automatizados.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root)

    try:
        Migrator(root=root, dry_run=args.dry_run).run(
            include_tests=not args.no_tests
        )
        return 0
    except Exception as exc:
        print(f"Erro durante a migração: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

