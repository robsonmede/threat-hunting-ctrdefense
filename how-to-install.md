
python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

python -c "import hashlib; print(hashlib.sha256(b'SUA_SENHA').hexdigest())"

.streamlit/secrets.toml
"HASH_SHA256_DA_SENHA"

streamlit run app.py

http://localhost:8501

streamlit run app.py --server.address 0.0.0.0

Validação do projeto
python -m compileall core services utils pages app.py

