from typing import Any
from urllib.parse import quote
import requests
from services.http import get_http_session
from utils.helpers import is_valid_email

HTTP = get_http_session()

# Endpoint para verificação rápida (status)
CHECK_EMAIL_URL = "https://api.xposedornot.com/v1/check-email/"
# Endpoint para relatório completo (breach-analytics)
BREACH_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"

def query_xposedornot(email: str, api_key: str | None = None) -> dict[str, Any]:
    """
    Consulta vazamentos detalhados associados a um e-mail.
    Prioriza o endpoint 'breach-analytics' para um relatório completo.
    """
    email = (email or "").strip().lower()
    if not is_valid_email(email):
        return {"error": "E-mail inválido"}

    headers = {
        "Accept": "application/json",
        "User-Agent": "ThreatIntelStreamlit/3.9",
    }
    if api_key:
        headers["x-api-key"] = api_key

    try:
        # A API de analytics é o endpoint mais completo para relatórios de vazamento
        response = HTTP.get(
            BREACH_ANALYTICS_URL,
            params={"email": email},
            headers=headers,
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "email": email,
                "status": "SEGURO",
                "breaches_found": 0,
                "breach_list": [],
                "total_records": 0,
            }

        if response.status_code != 200:
            return {"error": f"Erro {response.status_code} na consulta ao XposedOrNot"}

        data = response.json()
        
        # O endpoint de analytics retorna os vazamentos em 'ExposedBreaches'
        # ou 'exposedBreaches' dependendo da versão da API
        exposed_data = data.get("ExposedBreaches") or data.get("exposedBreaches") or {}
        
        # Normaliza a lista de vazamentos
        breaches = exposed_data.get("breaches_details") or exposed_data.get("breaches") or []
        
        breach_list = []
        total_records = 0

        for b in breaches:
            # Estrutura padronizada para a UI
            records = b.get("xposed_records") or b.get("records_exposed") or 0
            try:
                records = int(records)
            except:
                records = 0
            
            total_records += records
            
            breach_list.append({
                "name": b.get("breach") or b.get("name") or "N/D",
                "title": b.get("breach") or b.get("name") or "N/D",
                "date": b.get("xposed_date") or b.get("breach_date") or "N/D",
                "records_exposed": records,
                "data_classes": b.get("xposed_data") or b.get("data_classes") or "N/D",
                "description": b.get("details") or b.get("description") or "",
            })

        count = len(breach_list)
        
        return {
            "email": email,
            "status": "ALTO RISCO" if count > 0 else "SEGURO",
            "breaches_found": count,
            "breach_list": breach_list,
            "total_records": total_records,
            "raw_data": data,
        }

    except Exception as exc:
        return {"error": f"Erro na consulta: {str(exc)}"}

