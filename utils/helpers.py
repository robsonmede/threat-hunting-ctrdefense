from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?)+$"
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def normalize_ioc(value: str) -> str:
    """Normaliza um indicador de comprometimento."""
    return str(value or "").strip().lower().rstrip(".,;:)]}")


def is_valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(
            str(value).strip()
        ).version == 4
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(
            str(value).strip()
        ).version == 6
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    return is_valid_ipv4(value) or is_valid_ipv6(value)


def is_valid_email(value: str) -> bool:
    return bool(
        EMAIL_PATTERN.fullmatch(
            str(value or "").strip()
        )
    )


def is_valid_domain(value: str) -> bool:
    value = str(value or "").strip().lower().rstrip(".")
    return bool(DOMAIN_PATTERN.fullmatch(value))


def is_valid_hash(value: str) -> bool:
    value = str(value or "").strip().lower()

    return (
        len(value) in {32, 40, 64}
        and all(
            character in "0123456789abcdef"
            for character in value
        )
    )


def is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(str(value or "").strip())

        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
        )
    except ValueError:
        return False


def detect_ioc_type(value: str) -> str:
    value = normalize_ioc(value)

    if is_valid_ip(value):
        return "ip"

    if is_valid_hash(value):
        return "hash"

    if is_valid_email(value):
        return "email"

    if is_valid_url(value):
        return "url"

    if is_valid_domain(value):
        return "domain"

    return "unknown"
