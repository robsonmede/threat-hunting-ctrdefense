import streamlit as st
from services.http import get_http_session
from utils.helpers import is_valid_ipv4, is_valid_ipv6

HTTP = get_http_session()

ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning", 
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}

def check_abuseipdb(api_key, ip_address, max_age_days=90):
    """
    Consulta o AbuseIPDB para reputação de IP.
    
    Args:
        api_key: Chave API do AbuseIPDB
        ip_address: Endereço IP para consulta
        max_age_days: Dias máximos para considerar reports (1-365)
    
    Returns:
        dict: Dados da reputação ou erro
    """
    # Validação do IP
    if not is_valid_ipv4(ip_address) and not is_valid_ipv6(ip_address):
        return {"error": "Endereço IP inválido"}
    
    if not api_key:
        return {"error": "API Key do AbuseIPDB não configurada"}
    
    # Limitar max_age_days
    max_age_days = max(1, min(365, int(max_age_days)))
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key,
        "User-Agent": "ThreatIntelStreamlit/3.9"
    }
    
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": str(max_age_days),
        "verbose": "true"
    }
    
    try:
        response = HTTP.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()["data"]
            
            # Processar categorias de abuso
            category_counts = {}
            reports = data.get("reports", []) or []
            
            for report in reports:
                categories = report.get("categories", []) or []
                for cat_id in categories:
                    name = ABUSEIPDB_CATEGORIES.get(cat_id, f"Categoria {cat_id}")
                    category_counts[name] = category_counts.get(name, 0) + 1
            
            # Top 5 categorias
            top_categories = sorted(
                category_counts.items(), 
                key=lambda kv: kv[1], 
                reverse=True
            )[:5]
            
            # Determinar status baseado no score
            score = data.get("abuseConfidenceScore", 0)
            if score >= 75:
                status = "🚨 ALTO RISCO"
                status_color = "status-danger"
            elif score >= 50:
                status = "🟡 RISCO MODERADO"
                status_color = "status-warn"
            elif score >= 25:
                status = "🟠 RISCO BAIXO"
                status_color = "status-warn"
            else:
                status = "✅ BAIXO RISCO"
                status_color = "status-safe"
            
            return {
                "ip": ip_address,
                "status": status,
                "status_color": status_color,
                "score": f"{score}%",
                "score_raw": score,
                "reports": data.get("totalReports", 0),
                "distinct_reporters": data.get("numDistinctUsers", 0),
                "country": data.get("countryCode") or "N/D",
                "country_name": data.get("countryName") or "N/D",
                "isp": data.get("isp") or "N/D",
                "domain": data.get("domain") or "N/D",
                "hostnames": data.get("hostnames") or [],
                "usage_type": data.get("usageType") or "N/D",
                "is_whitelisted": data.get("isWhitelisted", False),
                "is_public": data.get("isPublic", False),
                "is_tor": data.get("isTor", False),
                "last_reported_at": data.get("lastReportedAt") or "Nunca reportado",
                "top_categories": top_categories,
                "category_counts": category_counts,
                "raw_data": data,
            }
            
        elif response.status_code == 429:
            return {"error": "Limite de requisições do AbuseIPDB atingido. Tente novamente mais tarde."}
        elif response.status_code == 401:
            return {"error": "API Key do AbuseIPDB inválida ou expirada"}
        elif response.status_code == 422:
            return {"error": "IP inválido ou mal formatado"}
        else:
            return {"error": f"Erro HTTP {response.status_code}: {response.text[:200]}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao AbuseIPDB"}
    except requests.exceptions.ConnectionError:
        return {"error": "Erro de conexão com AbuseIPDB"}
    except Exception as e:
        return {"error": f"Erro inesperado: {str(e)}"}
