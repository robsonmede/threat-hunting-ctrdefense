import streamlit as st
from services.http import get_http_session
from utils.helpers import is_valid_ipv4, is_valid_domain

HTTP = get_http_session()

def query_rdap(target):
    """
    Consulta informações RDAP (Registration Data Access Protocol).
    
    Args:
        target: IP, ASN ou domínio
    
    Returns:
        dict: Dados RDAP
    """
    # Determinar tipo e endpoint
    if is_valid_ipv4(target):
        endpoint = f"https://rdap.db.ripe.net/ip/{target}"
    elif target.upper().startswith("AS"):
        asn = target[2:] if target.upper().startswith("AS") else target
        endpoint = f"https://rdap.db.ripe.net/autnum/{asn}"
    elif is_valid_domain(target):
        endpoint = f"https://rdap.org/domain/{target}"
    else:
        return {"error": "Alvo inválido para RDAP"}
    
    try:
        response = HTTP.get(endpoint, timeout=8)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extrair informações relevantes
            events = data.get("events", []) or []
            entities = data.get("entities", []) or []
            notices = data.get("notices", []) or []
            
            # Encontrar registrante
            registrant = "N/D"
            for entity in entities:
                if "registrant" in (entity.get("roles", []) or []):
                    registrant = entity.get("vcardArray", [{}])[1] or {}
                    break
            
            return {
                "target": target,
                "handle": data.get("handle", "N/D"),
                "name": data.get("name", "N/D"),
                "type": data.get("type", "N/D"),
                "start_date": data.get("startDate", "N/D"),
                "end_date": data.get("endDate", "N/D"),
                "registrant": registrant,
                "events": len(events),
                "entities": len(entities),
                "notices": len(notices),
                "raw_data": data,
            }
        elif response.status_code == 404:
            return {"error": "Registro não encontrado no RDAP"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta RDAP"}
    except Exception as e:
        return {"error": f"Erro inesperado: {str(e)}"}
