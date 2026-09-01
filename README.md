
# 🛡️ Cyber Threat Research

Plataforma modular de **Threat Intelligence** desenvolvida em Python e Streamlit para extração, classificação e análise de Indicadores de Comprometimento — IOCs.

O projeto foi criado para apoiar atividades autorizadas de investigação, resposta a incidentes, análise OSINT e pesquisa defensiva em segurança da informação.

> **Utilize esta ferramenta somente em ambientes próprios, autorizados, educacionais ou defensivos.**

---

## 📌 Funcionalidades

- Extração automática de IOCs a partir de textos, logs e relatórios;
- Identificação de:
  - Endereços IPv4 e IPv6;
  - Hashes MD5, SHA-1 e SHA-256;
  - Domínios;
  - URLs;
  - Endereços de e-mail;
- Consulta de reputação de IPs no AbuseIPDB;
- Consulta de IPs, hashes, domínios e URLs no VirusTotal;
- Classificação automática de indicadores;
- Módulo central de Threat Intelligence;
- Verificação de possível exposição de e-mails;
- Histórico de consultas durante a sessão;
- Exportação de dados em CSV, JSON e Excel;
- Interface web com tema Cyberpunk/Glassmorphism;
- Arquitetura modular para facilitar manutenção e expansão.

---

## 🧱 Estrutura do projeto

```text
threat-intel-streamlit/
├── app.py
├── requirements.txt
├── README.md
├── DISCLAIMER.md
│
├── core/
│   ├── __init__.py
│   ├── auth.py
│   ├── css.py
│   └── sidebar.py
│
├── services/
│   ├── __init__.py
│   ├── http.py
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── urlscan.py
│   ├── shodan.py
│   ├── ipapi.py
│   ├── rdap.py
│   ├── nvd.py
│   ├── crtsh.py
│   ├── malwarebazaar.py
│   ├── botscout.py
│   └── xposedornot.py
│
├── utils/
│   ├── __init__.py
│   ├── helpers.py
│   └── export.py
│
└── pages/
    ├── 1_Extrator_IOCs.py
    ├── 2_AbuseIPDB.py
    ├── 3_VirusTotal.py
    ├── 4_Threat_Intelligence.py
    ├── 5_Relatorios.py
    └── 6_Vazamento_Email.py
