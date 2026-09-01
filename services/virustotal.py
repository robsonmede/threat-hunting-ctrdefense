import base64
import urllib.parse
from datetime import datetime, timezone
import streamlit as st
from services.http import get_http_session

HTTP = get_http_session()

_VT_IP_DEFAULTS = {
    "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0,
    "country": "N/D", "as_owner": "N/D", "asn": "N/D", "network": "N/D", "rir": "N/D",
    "votes_malicious": 0, "votes_harmless": 0, "last_analysis_human": "N/D",
    "malicious_engines": [],
}

def get_vt_data(api_key, endpoint, item_id):
    """Consulta a API do VirusTotal."""
    if not api_key:
        return {"error": "Chave API não configurada"}
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "x-tool": "threat-intel-streamlit-v3.9"
    }
    
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{item_id}"
    
    try:
        response = HTTP.get(url, headers=headers, timeout=12)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Não encontrado no VirusTotal"}
        elif response.status_code == 429:
            return {"error": "Limite de requisições excedido (Rate Limit)"}
        elif response.status_code == 401:
            return {"error": "API Key inválida ou expirada"}
        else:
            return {"error": f"Erro HTTP {response.status_code}: {response.text[:100]}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao VirusTotal"}
    except requests.exceptions.ConnectionError:
        return {"error": "Erro de conexão com VirusTotal"}
    except Exception as e:
        return {"error": f"Erro inesperado: {str(e)}"}

def parse_vt_details(vt_response):
    """Processa a resposta do VirusTotal para extrair informações estruturadas."""
    if "error" in vt_response:
        base = {
            "verdict": f"⚠️ {vt_response['error']}", 
            "score": "N/A", 
            "tags": "N/A", 
            "file_name": "N/D", 
            "file_type": "N/D", 
            "file_size": "N/D"
        }
        base.update(_VT_IP_DEFAULTS)
        return base
    
    try:
        attrs = vt_response["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values())
        
        # Tags e nomes
        tags = attrs.get("tags", [])[:3]
        meaningful_name = attrs.get("meaningful_name", "")
        names_list = attrs.get("names", [])
        primary_name = meaningful_name if meaningful_name else (names_list[0] if names_list else "Desconhecido")
        file_type = attrs.get("type_description", attrs.get("magic", "N/D"))
        file_size = attrs.get("size", "N/D")
        
        # Determinar veredito
        if malicious > 0:
            verdict = f"🚨 Malicioso ({malicious}/{total})"
            score_color = "status-danger"
        elif suspicious > 0:
            verdict = f"🟡 Suspeito ({suspicious}/{total})"
            score_color = "status-warn"
        else:
            verdict = f"✅ Limpo ({harmless}/{total})"
            score_color = "status-safe"
        
        # Engines maliciosos
        malicious_engines = []
        analysis_results = attrs.get("last_analysis_results", {}) or {}
        for engine, res in analysis_results.items():
            if isinstance(res, dict) and res.get("category") in ("malicious", "suspicious"):
                malicious_engines.append({
                    "engine": engine,
                    "result": res.get("result", "N/D"),
                    "category": res.get("category", "N/D")
                })
        
        # Votos da comunidade
        votes = attrs.get("total_votes", {}) or {}
        
        # Timestamp da última análise
        last_analysis_ts = attrs.get("last_analysis_date")
        last_analysis_human = "N/D"
        if isinstance(last_analysis_ts, (int, float)):
            try:
                last_analysis_human = datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
            except (OSError, OverflowError, ValueError):
                last_analysis_human = "N/D"
        
        # Informações de rede (para IPs)
        country = attrs.get("country", "N/D")
        as_owner = attrs.get("as_owner", "N/D")
        asn = attrs.get("asn", "N/D")
        network = attrs.get("network", "N/D")
        rir = attrs.get("regional_internet_registry", "N/D")
        
        return {
            "verdict": verdict,
            "score_color": score_color,
            "score": attrs.get("reputation", 0),
            "tags": ", ".join(tags) if tags else "Sem Tags",
            "file_name": primary_name,
            "file_type": file_type,
            "file_size": f"{file_size:,} bytes" if isinstance(file_size, int) else str(file_size),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "country": country,
            "as_owner": as_owner,
            "asn": asn,
            "network": network,
            "rir": rir,
            "votes_malicious": votes.get("malicious", 0),
            "votes_harmless": votes.get("harmless", 0),
            "last_analysis_human": last_analysis_human,
            "malicious_engines": malicious_engines[:10],  # Limitar a 10 engines
            "raw_stats": stats,
        }
        
    except KeyError as e:
        return {
            "verdict": f"⚠️ Erro na estrutura da resposta (campo {e})",
            "score": "N/A",
            "tags": "N/D",
            "file_name": "N/D",
            "file_type": "N/D",
            "file_size": "N/D",
            **{k: "N/D" for k in _VT_IP_DEFAULTS.keys()}
        }

def vt_url_id(value):
    """Codifica URL para ID do VirusTotal (base64 URL-safe)."""
    try:
        encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=")
    except Exception:
        return value

def query_vt_universal(api_key, value, kind):
    """
    Consulta universal para VirusTotal.
    
    Args:
        api_key: Chave API do VirusTotal
        value: Valor a consultar (IP, hash, URL, domínio)
        kind: Tipo do valor ("IP", "MD5", "SHA1", "SHA256", "URL", "DOMAIN")
    
    Returns:
        dict: Resposta do VirusTotal ou erro
    """
    if not api_key:
        return {"error": "VirusTotal: API Key não configurada"}
    
    # Mapeamento de tipos para endpoints
    endpoint_map = {
        "IP": "ip_addresses",
        "MD5": "files",
        "SHA1": "files",
        "SHA256": "files",
        "URL": "urls",
        "DOMAIN": "domains",
    }
    
    endpoint = endpoint_map.get(kind)
    if not endpoint:
        return {"error": f"VirusTotal não suporta o tipo '{kind}'"}
    
    # Para URLs, precisa codificar
    item_id = vt_url_id(value) if kind == "URL" else value
    
    return get_vt_data(api_key, endpoint, item_id)
