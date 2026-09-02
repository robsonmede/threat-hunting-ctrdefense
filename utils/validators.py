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
