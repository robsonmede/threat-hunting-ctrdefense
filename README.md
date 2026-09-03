
# 🛡️Threat Research v3.9

Plataforma modular de **Threat Intelligence** desenvolvida em Python e Streamlit para extração, classificação e análise de Indicadores de Comprometimento — IOCs.

O projeto foi criado para apoiar atividades autorizadas de investigação, resposta a incidentes, análise OSINT e pesquisa defensiva em segurança da informação.

> **Utilize esta ferramenta somente em ambientes próprios, autorizados, educacionais ou defensivos.**

<img src="https://ctrdefense.io/wp-content/uploads/2026/09/threat-research.png" alt="Threat Research">

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

´´´text
#INSTALL APP SERVER

python3 -m venv .venv
source .venv/bin/activate

pip install pandas
pip install -r requirements.txt

python -c "import hashlib; print(hashlib.sha256(b'SUA_SENHA').hexdigest())"

.streamlit/secrets.toml "HASH_SHA256_DA_SENHA"

streamlit run app.py

http://localhost:8501

streamlit run app.py --server.address 0.0.0.0

Validação do projeto python -m compileall core services utils pages app.py
