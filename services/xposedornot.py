from typing import Any
from urllib.parse import quote

import requests

from services.http import get_http_session
from utils.helpers import is_valid_email


HTTP = get_http_session()
XPOSEDORNOT_URL = "https://api.xposedornot.com/v1/check-email/"


def query_xposedornot(
    email: str,
    api_key: str | None = None,
) -> dict[str, Any]:
    """
    Consulta vazamentos associados a um e-mail no XposedOrNot.

    A API pública utiliza o endereço de e-mail codificado na URL.
    """

    email = (email or "").strip().lower()

    if not is_valid_email(email):
        return {"error": "E-mail inválido"}

    encoded_email = quote(email, safe="")
    url = f"{XPOSEDORNOT_URL}{encoded_email}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "ThreatIntelStreamlit/3.9",
    }

    if api_key:
        headers["x-api-key"] = api_key

    try:
        response = HTTP.get(
            url,
            headers=headers,
            timeout=15,
        )

        if response.status_code in (404, 204):
            return {
                "email": email,
                "status": "SEGURO",
                "breaches_found": 0,
                "message": (
                    "Nenhum vazamento conhecido foi encontrado."
                ),
                "breach_list": [],
                "total_records": 0,
                "raw_data": {},
            }

        if response.status_code == 401:
            return {"error": "Chave da API inválida ou não autorizada"}

        if response.status_code == 429:
            return {"error": "Limite de requisições excedido"}

        if response.status_code != 200:
            return {
                "error": (
                    f"Erro HTTP {response.status_code} "
                    "na consulta ao XposedOrNot"
                )
            }

        data = response.json()

        breaches = (
            data.get("breaches")
            or data.get("Breaches")
            or data.get("data")
            or []
        )

        if isinstance(breaches, dict):
            breaches = breaches.get("breaches", [])

        if not isinstance(breaches, list):
            breaches = []

        breach_list = []
        total_records = 0

        for breach in breaches[:20]:
            if isinstance(breach, str):
                breach_info = {
                    "name": breach,
                    "title": breach,
                    "date": "N/D",
                    "records_exposed": 0,
                    "data_classes": [],
                    "description": "",
                }
            else:
                records = breach.get("PwnCount", 0) or breach.get(
                    "records_exposed", 0
                )

                try:
                    records = int(records)
                except (TypeError, ValueError):
                    records = 0

                data_classes = (
                    breach.get("DataClasses")
                    or breach.get("data_classes")
                    or []
                )

                breach_info = {
                    "name": breach.get("Name")
                    or breach.get("name")
                    or "N/D",
                    "title": breach.get("Title")
                    or breach.get("title")
                    or "N/D",
                    "date": breach.get("BreachDate")
                    or breach.get("date")
                    or "N/D",
                    "records_exposed": records,
                    "data_classes": data_classes[:20],
                    "description": (
                        breach.get("Description")
                        or breach.get("description")
                        or ""
                    )[:500],
                }

                total_records += records

            breach_list.append(breach_info)

        count = len(breaches)

        if count >= 5:
            status = "ALTO RISCO"
        elif count >= 2:
            status = "RISCO MODERADO"
        elif count == 1:
            status = "RISCO BAIXO"
        else:
            status = "SEGURO"

        return {
            "email": email,
            "status": status,
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

    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao XposedOrNot"}
    except requests.exceptions.RequestException as exc:
        return {
            "error": f"Erro de conexão com o XposedOrNot: {exc}"
        }
    except ValueError:
        return {"error": "Resposta JSON inválida do XposedOrNot"}
    except Exception as exc:
        return {"error": f"Erro inesperado: {exc}"}
