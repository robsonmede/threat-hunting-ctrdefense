from __future__ import annotations

from pathlib import Path
from datetime import datetime
import shutil


ROOT = Path(__file__).resolve().parent
AUTH_FILE = ROOT / "core" / "auth.py"


COMPATIBILITY_CODE = r'''

# ---------------------------------------------------------------------
# Compatibilidade com páginas antigas
# ---------------------------------------------------------------------

def check_password() -> bool:
    """
    Compatibilidade com páginas que ainda utilizam:

        from core.auth import check_password

    Retorna True quando o usuário está autenticado.
    Caso contrário, exibe o formulário de login e retorna False.
    """
    return require_login()
'''


def create_backup(file_path: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = file_path.with_name(
        f"{file_path.stem}.backup_{timestamp}{file_path.suffix}"
    )

    shutil.copy2(file_path, backup_path)
    return backup_path


def patch_auth_file() -> None:
    if not AUTH_FILE.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {AUTH_FILE}"
        )

    content = AUTH_FILE.read_text(encoding="utf-8")

    if "def check_password(" in content:
        print("A função check_password já existe.")
        return

    if "def require_login(" not in content:
        raise RuntimeError(
            "A função require_login não foi encontrada em core/auth.py. "
            "Verifique o conteúdo do arquivo antes de continuar."
        )

    backup_path = create_backup(AUTH_FILE)

    updated_content = content.rstrip() + COMPATIBILITY_CODE + "\n"
    AUTH_FILE.write_text(updated_content, encoding="utf-8")

    print("Correção aplicada com sucesso.")
    print(f"Backup criado em: {backup_path}")
    print(f"Arquivo atualizado: {AUTH_FILE}")


def update_page_imports() -> None:
    pages_dir = ROOT / "pages"

    if not pages_dir.exists():
        print("Pasta pages não encontrada. Nenhuma página foi alterada.")
        return

    changed_files = []

    for page_file in pages_dir.glob("*.py"):
        content = page_file.read_text(encoding="utf-8")

        if "from core.auth import check_password" not in content:
            continue

        # O import continua válido depois da criação da função compatível.
        # Portanto, não é necessário alterar as páginas.
        changed_files.append(page_file.name)

    if changed_files:
        print("\nPáginas que usam check_password:")
        for file_name in changed_files:
            print(f" - {file_name}")
    else:
        print("\nNenhuma página com import direto de check_password encontrada.")


def validate_syntax() -> None:
    import py_compile

    try:
        py_compile.compile(
            str(AUTH_FILE),
            doraise=True,
        )
        print("\nSintaxe de core/auth.py validada com sucesso.")
    except py_compile.PyCompileError as error:
        print("\nERRO: a sintaxe de core/auth.py continua inválida.")
        print(error)
        raise


if __name__ == "__main__":
    print("=== Correção de compatibilidade do sistema de autenticação ===")

    patch_auth_file()
    update_page_imports()
    validate_syntax()

    print("\nConcluído.")
    print("Agora reinicie o Streamlit com:")
    print("  pkill -f streamlit")
    print("  streamlit run app.py")

