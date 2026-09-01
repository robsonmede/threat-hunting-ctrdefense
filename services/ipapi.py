import streamlit as st
from services.http import get_http_session
from utils.helpers import is_valid_ipv4, is_valid_ipv6

HTTP = get_http_session()

def query_ip_api(ip_address, api_key=None):
    """
    Consulta informações geográficas e de rede de um IP.
    Usa ip-api.com (gratuito com limites).
    
    Args:
        ip_address: Endereço IP para consulta
        api_key: Chave API do ip-api (opcional para plano pro)
    
    Returns:
        dict: Dados geográficos e de rede
    """
    if not (is_valid_ipv4(ip_address) or is_valid_ipv6(ip_address)):
        return {"error": "Endereço IP inválido"}
    
    # Usar endpoint apropriado
    endpoint = "http://ip-api.com/json/"
    if api_key:
        endpoint = f"http://pro.ip-api.com/json/{ip_address}?key={api_key}"
    else:
        endpoint = f"{endpoint}{ip_address}"
    
    try:
        response = HTTP.get(endpoint, timeout=6)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("status") == "fail":
                return {"error": data.get("message", "Falha na consulta")}
            
            return {
                "ip": ip_address,
                "country": data.get("country", "N/D"),
                "country_code": data.get("countryCode", "N/D"),
                "region": data.get("regionName", "N/D"),
                "city": data.get("city", "N/D"),
                "zip": data.get("zip", "N/D"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "timezone": data.get("timezone", "N/D"),
                "isp": data.get("isp", "N/D"),
                "org": data.get("org", "N/D"),
                "as": data.get("as", "N/D"),
                "asn": data.get("as", "N/D").split()[0] if data.get("as") else "N/D",
                "mobile": data.get("mobile", False),
                "proxy": data.get("proxy", False),
                "hosting": data.get("hosting", False),
                "raw_data": data,
            }
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao ip-api"}
    except Exception as e:
        return {"error": f"Erro inesperado: {str(e)}"}
