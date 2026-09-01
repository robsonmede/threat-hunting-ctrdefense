import streamlit as st
from services.http import get_http_session
from utils.helpers import is_valid_ipv4, is_valid_domain

HTTP = get_http_session()

def query_shodan_internetdb(api_key, ip_address):
    """
    Consulta o Shodan InternetDB para informações de IP.
    Usa a API pública do InternetDB (não requer chave Shodan paga).
    
    Args:
        api_key: Chave API do Shodan (opcional para InternetDB)
        ip_address: Endereço IP para consulta
    
    Returns:
        dict: Dados do InternetDB
    """
    if not is_valid_ipv4(ip_address):
        return {"error": "Endereço IPv4 inválido"}
    
    url = f"https://internetdb.shodan.io/{ip_address}"
    
    try:
        response = HTTP.get(url, timeout=8)
        
        if response.status_code == 200:
            data = response.json()
            
            # Determinar status baseado em vulnerabilidades
            vulns = data.get("vulns", []) or []
            cpes = data.get("cpes", []) or []
            ports = data.get("ports", []) or []
            hostnames = data.get("hostnames", []) or []
            tags = data.get("tags", []) or []
            
            risk_level = "BAIXO"
            if vulns:
                risk_level = "ALTO" if len(vulns) > 3 else "MODERADO"
            
            return {
                "ip": ip_address,
                "risk_level": risk_level,
                "vulnerabilities": len(vulns),
                "vuln_list": vulns[:5],  # Top 5
                "cpes": len(cpes),
                "cpe_list": cpes[:5],
                "ports": len(ports),
                "port_list": ports[:10],
                "hostnames": len(hostnames),
                "hostname_list": hostnames[:5],
                "tags": tags,
                "raw_data": data,
            }
        elif response.status_code == 404:
            return {"error": "IP não encontrado no InternetDB"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao Shodan InternetDB"}
    except Exception as e:
        return {"error": f"Erro inesperado: {str(e)}"}

def query_shodan_api(api_key, query):
    """
    Consulta a API completa do Shodan (requer chave paga).
    
    Args:
        api_key: Chave API do Shodan
        query: Query de busca (ex: "apache", "port:80", "country:BR")
    
    Returns:
        dict: Resultados da busca
    """
    if not api_key:
        return {"error": "API Key do Shodan não configurada"}
    
    url = "https://api.shodan.io/shodan/host/search"
    params = {
        "key": api_key,
        "query": query,
        "minify": "true",
        "page": 1
    }
    
    try:
        response = HTTP.get(url, params=params, timeout=12)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            return {"error": "API Key do Shodan inválida"}
        elif response.status_code == 429:
            return {"error": "Limite de requisições do Shodan atingido"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}
