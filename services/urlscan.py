import streamlit as st
from services.http import get_http_session
from utils.helpers import is_valid_url, is_valid_domain
import time

HTTP = get_http_session()

def scan_urlscan(api_key, target, visibility="public", tags=None):
    """
    Submete uma URL para análise no urlscan.io.
    
    Args:
        api_key: Chave API do urlscan.io
        target: URL ou domínio para scan
        visibility: "public" ou "private"
        tags: Lista de tags para a análise
    
    Returns:
        dict: Resultado do scan ou erro
    """
    if not api_key:
        return {"error": "API Key do urlscan.io não configurada"}
    
    # Validar target
    if not (is_valid_url(target) or is_valid_domain(target)):
        return {"error": "URL ou domínio inválido"}
    
    url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "Content-Type": "application/json",
        "API-Key": api_key,
        "User-Agent": "ThreatIntelStreamlit/3.9"
    }
    
    payload = {
        "url": target,
        "visibility": visibility,
        "tags": tags or ["threat-intel", "streamlit"]
    }
    
    try:
        # Submeter scan
        response = HTTP.post(url, headers=headers, json=payload, timeout=15)
        
        if response.status_code == 200:
            submission = response.json()
            scan_id = submission.get("uuid")
            result_url = submission.get("result")
            api_url = submission.get("api")
            
            # Aguardar resultado (polling)
            if api_url:
                for _ in range(10):  # 10 tentativas
                    time.sleep(2)
                    result_resp = HTTP.get(api_url, timeout=10)
                    
                    if result_resp.status_code == 200:
                        result_data = result_resp.json()
                        
                        # Extrair informações relevantes
                        verdict = result_data.get("verdicts", {}).get("overall", {})
                        page_data = result_data.get("page", {})
                        stats = result_data.get("stats", {})
                        lists = result_data.get("lists", {})
                        
                        return {
                            "status": "COMPLETO",
                            "scan_id": scan_id,
                            "result_url": result_url,
                            "target": target,
                            "malicious": verdict.get("malicious", False),
                            "score": verdict.get("score", 0),
                            "categories": verdict.get("categories", []),
                            "ip": page_data.get("ip"),
                            "country": page_data.get("country"),
                            "server": page_data.get("server"),
                            "domain": page_data.get("domain"),
                            "url": page_data.get("url"),
                            "adblock": stats.get("adblock", 0),
                            "https": stats.get("https", 0),
                            "malware_urls": len(lists.get("urls", [])),
                            "malware_ips": len(lists.get("ips", [])),
                            "raw_data": result_data,
                        }
                
                return {"error": "Timeout aguardando resultado do scan"}
            else:
                return {"error": "Resposta inesperada da API"}
                
        elif response.status_code == 429:
            return {"error": "Limite de requisições do urlscan.io atingido"}
        elif response.status_code == 400:
            return {"error": "Requisição inválida (URL malformada ou bloqueada)"}
        elif response.status_code == 401:
            return {"error": "API Key do urlscan.io inválida"}
        else:
            return {"error": f"Erro HTTP {response.status_code}: {response.text[:200]}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout na comunicação com urlscan.io"}
    except Exception as e:
        return {"error": f"Erro inesperado: {str(e)}"}

def get_urlscan_result(scan_id, api_key=None):
    """
    Recupera resultado de um scan existente.
    
    Args:
        scan_id: UUID do scan
        api_key: Chave API (opcional para scans públicos)
    
    Returns:
        dict: Dados do scan
    """
    url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    headers = {"User-Agent": "ThreatIntelStreamlit/3.9"}
    
    if api_key:
        headers["API-Key"] = api_key
    
    try:
        response = HTTP.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Scan não encontrado"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
