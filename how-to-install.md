git clone https://github.com/SEU_USUARIO/threat-intel-streamlit.git
cd threat-hunting-ctrdefense

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

streamlit>=1.40
requests>=2.31
pandas>=2.0
openpyxl>=3.1

.env
.streamlit/secrets.toml
credentials.json
config.json

 .gitignore:
 
 .venv/
__pycache__/
*.pyc
.env
.streamlit/secrets.toml
credentials.json
config.json

.streamlit/secrets.toml

APP_PASSWORD_HASH = "HASH_SHA256_DA_SENHA"

python -c "import hashlib; print(hashlib.sha256(b'SUA_SENHA').hexdigest())"

streamlit run app.py

http://localhost:8501

streamlit run app.py --server.address 0.0.0.0

Validação do projeto
python -m compileall core services utils pages app.py

python -c "import app"
