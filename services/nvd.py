import streamlit as st
from services.http import get_http_session
import re

HTTP = get_http_session()

def query_cve_details(cve_id):
    """
    Consulta detalhes de uma CVE no NVD (National Vulnerability Database).
    
    Args:
        cve_id: ID da CVE (ex: CVE-2021-44228)
    
    Returns:
        dict: Detalhes da vulnerabilidade
    """
    # Validar formato CVE
    cve_pattern = r'^CVE-\d{4}-\d{4,}$'
    if not re.match(cve_pattern, cve_id, re.IGNORECASE):
        return {"error": "Formato CVE inválido. Use CVE-AAAA-NNNN"}
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        response = HTTP.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if not data.get("vulnerabilities"):
                return {"error": "CVE não encontrada no NVD"}
            
            vuln = data["vulnerabilities"][0]["cve"]
            metrics = vuln.get("metrics", {}) or {}
            
            # Extrair CVSS v3.1
            cvss_data = {}
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_data = {
                    "score": cvss.get("baseScore", 0),
                    "severity": cvss.get("baseSeverity", "N/D"),
                    "vector": cvss.get("vectorString", "N/D"),
                }
            
            # Descrição
            descriptions = vuln.get("descriptions", []) or []
            description_en = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_en = desc.get("value", "")
                    break
            
            # Referências
            references = vuln.get("references", []) or []
            
            return {
                "cve_id": cve_id,
                "published": vuln.get("published", "N/D"),
                "last_modified": vuln.get("lastModified", "N/D"),
                "description": description_en[:500] + "..." if len(description_en) > 500 else description_en,
                "cvss_score": cvss_data.get("score", 0),
                "cvss_severity": cvss_data.get("severity", "N/D"),
                "cvss_vector": cvss_data.get("vector", "N/D"),
                "references": len(references),
                "reference_list": [ref.get("url") for ref in references[:5]],
                "raw_data": vuln,
            }
        elif response.status_code == 404:
            return {"error": "CVE não encontrada"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout na consulta ao NVD"}
    except Exception as e:
        return {"error": f"Erro inesperado: {str(e)}"}
