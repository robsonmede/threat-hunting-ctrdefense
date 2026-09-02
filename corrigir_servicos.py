from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
SERVICES_DIR = ROOT_DIR / "services"
PAGES_DIR = ROOT_DIR / "pages"

HTTP_FILE = SERVICES_DIR / "http.py"
INIT_FILE = SERVICES_DIR / "__init__.py"


HTTP_CONTENT = '''# services/http.py

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_TIMEOUT = 20


def get_http_session(
    *,
    retries: int = 2,
    backoff_factor: float = 0.5,
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Session:
    """
    Cria uma sessão HTTP reutilizável com retry automático.
    """

    session = requests.Session()

    retry_strategy = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(
            {
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
            }
        ),
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10,
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": "Cyber-Threat-Research/1.0",
        }
    )

    # O requests não possui timeout padrão nativo.
    # Este atributo será utilizado pelos helpers abaixo.
    session.request_timeout = timeout  # type: ignore[attr-defined]

    return session


def request_with_timeout(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Executa uma requisição utilizando o timeout configurado na sessão.
    """

    kwargs.setdefault(
        "timeout",
        getattr(session, "request_timeout", DEFAULT_TIMEOUT),
    )

    return session.request(
        method=method,
        url=url,
        **kwargs,
    )


def get(
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Executa uma requisição GET com sessão configurada.
    """

    session = get_http_session()

    return request_with_timeout(
        session,
        "GET",
        url,
        **kwargs,
    )


def post(
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Executa uma requisição POST com sessão configurada.
    """

    session = get_http_session()

    return request_with_timeout(
        session,
        "POST",
        url,
        **kwargs,
    )
'''


INIT_CONTENT = '''# services/__init__.py

"""
Integrações com serviços externos.

As importações não são realizadas automaticamente neste arquivo.
Isso evita importações circulares e impede que uma falha em um serviço
bloqueie o carregamento dos demais módulos.
"""
'''


def create_backup(file_path: Path) -> None:
    """Cria uma cópia de segurança do arquivo original."""

    if not file_path.exists():
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = file_path.with_name(
        f"{file_path.stem}.backup_{timestamp}{file_path.suffix}"
    )

    shutil.copy2(file_path, backup_path)
    print(f"[BACKUP] {file_path} -> {backup_path}")


def write_file(file_path: Path, content: str) -> None:
    """Cria o diretório e grava o conteúdo do arquivo."""

    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    print(f"[OK] Arquivo atualizado: {file_path}")


def validate_syntax() -> bool:
    """Executa o compileall para validar a sintaxe do projeto."""

    directories = [
        str(SERVICES_DIR),
        str(PAGES_DIR),
    ]

    command = [
        sys.executable,
        "-m",
        "compileall",
        "-q",
        *directories,
    ]

    print("\n[INFO] Validando a sintaxe dos arquivos...")

    result = subprocess.run(
        command,
        cwd=ROOT_DIR,
        check=False,
    )

    if result.returncode == 0:
        print("[OK] Validação de sintaxe concluída com sucesso.")
        return True

    print("[ERRO] Foram encontrados erros de sintaxe.")
    return False


def main() -> int:
    print("=== Correção dos serviços do projeto ===\n")

    if not SERVICES_DIR.exists():
        print(f"[ERRO] Diretório não encontrado: {SERVICES_DIR}")
        print("Execute este script na raiz do projeto.")
        return 1

    # Backup dos arquivos existentes
    create_backup(HTTP_FILE)
    create_backup(INIT_FILE)

    # Aplicação das correções
    write_file(HTTP_FILE, HTTP_CONTENT)
    write_file(INIT_FILE, INIT_CONTENT)

    # Validação
    if not validate_syntax():
        return 1

    print("\nCorreção concluída.")
    print("Agora reinicie o Streamlit com:")
    print("streamlit run app.py")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

