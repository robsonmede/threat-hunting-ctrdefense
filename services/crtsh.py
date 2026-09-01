from datetime import datetime, timezone
from typing import Any

import requests

from services.http import get_http_session
from utils.helpers import is_valid_domain


HTTP = get_http_session()


def query_crtsh(
    domain: str,
    include_expired: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    """
    Consulta certificados SSL/TLS associados a um domínio no crt.sh.
    """

    domain = (domain or "").strip().lower()

    if not is_valid_domain(domain):
        return {"error": "Domínio inválido"}

    limit = max(1, min(int(limit), 100))
    url = f"https://crt.sh/json?domain={domain}"

    if not include_expired:
        url += "&exclude=expired"

    try:
        response = HTTP.get(url, timeout=15)

        if response.status_code != 200:
            return {
                "error": (
                    f"Erro HTTP {response.status_code} "
                    "ao consultar o crt.sh"
                )
            }

        certificates = response.json()

        if not isinstance(certificates, list) or not certificates:
            return {
                "domain": domain,
                "total_certificates": 0,
                "certificates": [],
                "subdomain_list": [],
                "message": "Nenhum certificado encontrado",
            }

        processed = []
        certificate_ids = set()
        unique_subdomains = set()

        for certificate in certificates:
            certificate_id = certificate.get("id")

            if certificate_id in certificate_ids:
                continue

            certificate_ids.add(certificate_id)

            common_name = (
                certificate.get("common_name") or ""
            ).strip().lower()

            name_values = (
                certificate.get("name_value") or ""
            ).lower().splitlines()

            subdomains = sorted(
                {
                    value.strip()
                    for value in name_values
                    if value.strip()
                    and value.strip() != common_name
                    and (
                        value.strip() == domain
                        or value.strip().endswith(f".{domain}")
                    )
                }
            )

            unique_subdomains.update(subdomains)

            not_after = certificate.get("not_after") or ""
            is_expired = False

            if not_after:
                try:
                    expiry = datetime.fromisoformat(
                        not_after.replace("Z", "+00:00")
                    )

                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)

                    is_expired = expiry < datetime.now(timezone.utc)
                except (TypeError, ValueError):
                    is_expired = False

            processed.append(
                {
                    "id": certificate_id,
                    "common_name": common_name or "N/D",
                    "issuer": certificate.get("issuer_name") or "N/D",
                    "not_before": (
                        certificate.get("not_before") or "N/D"
                    ),
                    "not_after": not_after or "N/D",
                    "is_expired": is_expired,
                    "subdomains": subdomains[:20],
                    "subdomain_count": len(subdomains),
                    "entry_timestamp": certificate.get(
                        "entry_timestamp"
                    ),
                }
            )

            if len(processed) >= limit:
                break

        expired_count = sum(
            item["is_expired"] for item in processed
        )

        return {
            "domain": domain,
            "total_certificates": len(processed),
            "expired_certificates": expired_count,
            "active_certificates": len(processed) - expired_count,
            "unique_subdomains": len(unique_subdomains),
            "subdomain_list": sorted(unique_subdomains)[:100],
            "certificates": processed,
            "raw_count": len(certificates),
        }

    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao crt.sh"}
    except requests.exceptions.RequestException as exc:
        return {"error": f"Erro de conexão com o crt.sh: {exc}"}
    except ValueError:
        return {"error": "Resposta JSON inválida recebida do crt.sh"}
    except Exception as exc:
        return {"error": f"Erro inesperado: {exc}"}
