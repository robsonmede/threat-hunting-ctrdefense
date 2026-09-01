from typing import Any

import requests

from services.http import get_http_session
from utils.helpers import is_valid_email, is_valid_ipv4, is_valid_ipv6


HTTP = get_http_session()
BOTSCOUT_URL = "https://botscout.com/test/"


def query_botscout(
    value: str,
    value_type: str = "email",
    api_key: str = "demo",
) -> dict[str, Any]:
    """
    Consulta o BotScout.

    value_type pode ser:
        - email
        - ip
        - name
        - useragent
    """

    value = (value or "").strip()
    value_type = (value_type or "").strip().lower()

    allowed_types = {"email", "ip", "name", "useragent"}

    if not value:
        return {"error": "Valor não informado"}

    if value_type not in allowed_types:
        return {
            "error": (
                "Tipo inválido. Use email, ip, name ou useragent."
            )
        }

    if value_type == "email" and not is_valid_email(value):
        return {"error": "E-mail inválido"}

    if value_type == "ip" and not (
        is_valid_ipv4(value) or is_valid_ipv6(value)
    ):
        return {"error": "Endereço IP inválido"}

    params = {
        "multi": "",
        value_type: value,
        "key": api_key or "demo",
        "format": "json",
    }

    try:
        response = HTTP.get(
            BOTSCOUT_URL,
            params=params,
            timeout=10,
        )

        if response.status_code != 200:
            return {"error": f"Erro HTTP {response.status_code}"}

        data = response.json()
        match = str(data.get("match", "N")).upper() == "Y"

        try:
            frequency = int(data.get("frequency", 0) or 0)
        except (TypeError, ValueError):
            frequency = 0

        if not match:
            risk_level = "BAIXO"
        elif frequency > 100:
            risk_level = "ALTO"
        elif frequency > 10:
            risk_level = "MODERADO"
        else:
            risk_level = "LEVE"

        def split_values(key: str) -> list[str]:
            raw_value = data.get(key) or ""
            return [
                item.strip()
                for item in str(raw_value).split(",")
                if item.strip()
            ]

        names = split_values("names")
        emails = split_values("emails")
        ips = split_values("ips")
        useragents = split_values("useragents")

        return {
            "value": value,
            "type": value_type,
            "is_bot": match,
            "risk_level": risk_level,
            "frequency": frequency,
            "last_seen": data.get("lastseen") or "N/D",
            "bot_id": data.get("botid") or "N/D",
            "names_found": len(names),
            "names_list": names[:10],
            "emails_found": len(emails),
            "emails_list": emails[:10],
            "ips_found": len(ips),
            "ips_list": ips[:10],
            "useragents_found": len(useragents),
            "useragents_list": useragents[:10],
            "raw_data": data,
        }

    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao BotScout"}
    except requests.exceptions.RequestException as exc:
        return {"error": f"Erro de conexão com o BotScout: {exc}"}
    except ValueError:
        return {"error": "Resposta JSON inválida do BotScout"}
    except Exception as exc:
        return {"error": f"Erro inesperado: {exc}"}


def multi_check_botscout(
    emails: list[str] | None = None,
    ips: list[str] | None = None,
    names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Executa verificações múltiplas no BotScout.
    """

    values_to_check = []

    for email in (emails or [])[:10]:
        values_to_check.append((email, "email"))

    for ip in (ips or [])[:10]:
        values_to_check.append((ip, "ip"))

    for name in (names or [])[:10]:
        values_to_check.append((name, "name"))

    details = []
    bots_found = 0

    for value, value_type in values_to_check:
        result = query_botscout(value, value_type)
        details.append(result)

        if result.get("is_bot") is True:
            bots_found += 1

    return {
        "total_checked": len(details),
        "bots_found": bots_found,
        "details": details,
    }
