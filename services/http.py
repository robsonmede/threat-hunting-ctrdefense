import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import streamlit as st

@st.cache_resource(show_spinner=False)
def get_http_session():
    """
    Retorna uma sessão HTTP configurada com retry, pooling e timeouts.
    Cacheada para reutilização entre chamadas.
    """
    session = requests.Session()
    
    # Estratégia de retry para falhas temporárias
    retry_strategy = Retry(
        total=3,                      # Número total de tentativas
        connect=3,                    # Tentativas para erros de conexão
        read=2,                       # Tentativas para erros de leitura
        backoff_factor=0.6,           # Fator de espera exponencial
        status_forcelist=[429, 500, 502, 503, 504],  # Status para retry
        allowed_methods=["GET", "POST"],  # Métodos que permitem retry
        respect_retry_after_header=True,  # Respeitar cabeçalhos de retry-after
        raise_on_status=False,        # Não levantar exceção em status codes
    )
    
    # Adapter com pooling de conexões
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=20,          # Número máximo de conexões em pool
        pool_maxsize=20,              # Número máximo de conexões por host
        pool_block=False              # Não bloquear quando pool cheio
    )
    
    # Montar adapters para HTTP e HTTPS
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    # Configurações de timeout padrão
    session.timeout = (3.05, 10)      # (connect, read) em segundos
    
    # Headers padrão para evitar bloqueios
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (compatible; ThreatIntelStreamlit/3.9; +https://ctrdefense.io)',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
    })
    
    return session
