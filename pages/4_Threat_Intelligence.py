from datetime import datetime, timezone
import ipaddress
import re

import pandas as pd
import streamlit as st

from core.auth import check_password
from core.css import apply_cyberpunk_css
from ui_sidebar import aplicar_sidebar
from utils.export import save_history
from utils.helpers import detect_ioc_type


st.set_page_config(
    page_title="Threat Intelligence v3.9",
    page_icon="🧠",
    layout="wide",
)

aplicar_sidebar()
apply_cyberpunk_css()
check_password()


# ------------------------------------------------------------------
# Configurações
# ------------------------------------------------------------------

TIPOS_CONHECIDOS = {
    "ip": "Endereço IP",
    "domain": "Domínio",
    "url": "URL",
    "hash": "Hash",
    "cve": "Vulnerabilidade CVE",
    "email": "E-mail",
    "unknown": "Desconhecido",
}

RECOMENDACOES = {
    "ip": {
        "fonte": "AbuseIPDB / VirusTotal",
        "mensagem": (
            "Consulte reputação, denúncias, ASN, país, provedor "
            "e atividade maliciosa associada ao endereço IP."
        ),
    },
    "domain": {
        "fonte": "VirusTotal / WHOIS",
        "mensagem": (
            "Verifique reputação, DNS, certificados, data de registro "
            "e relacionamentos com outros indicadores."
        ),
    },
    "url": {
        "fonte": "VirusTotal / URLhaus",
        "mensagem": (
            "Analise reputação, redirecionamentos, arquivos entregues "
            "e mecanismos de detecção."
        ),
    },
    "hash": {
        "fonte": "VirusTotal / MalwareBazaar",
        "mensagem": (
            "Consulte detecções, nomes de malware, comportamento "
            "e relacionamentos com campanhas."
        ),
    },
    "cve": {
        "fonte": "NVD / CISA KEV",
        "mensagem": (
            "Verifique severidade, CVSS, produtos afetados, referências "
            "e evidências de exploração ativa."
        ),
    },
    "email": {
        "fonte": "Análise interna / bases autorizadas",
        "mensagem": (
            "Verifique exposição, domínio, contexto da ocorrência "
            "e possíveis campanhas de phishing."
        ),
    },
    "unknown": {
        "fonte": "Análise manual",
        "mensagem": (
            "O formato não foi reconhecido automaticamente. "
            "Revise o indicador antes de prosseguir."
        ),
    },
}


# ------------------------------------------------------------------
# Estado da sessão
# ------------------------------------------------------------------

if "resultados_threat_intelligence" not in st.session_state:
    st.session_state.resultados_threat_intelligence = []


# ------------------------------------------------------------------
# Funções auxiliares
# ------------------------------------------------------------------

def normalizar_indicador(valor: str) -> str:
    """Remove espaços e desfaz técnicas comuns de defang."""
    valor = valor.strip()

    substituicoes = {
        "hxxps://": "https://",
        "hxxp://": "http://",
        "HXXPS://": "https://",
        "HXXP://": "http://",
        "[.]": ".",
        "(.)": ".",
        "[:]": ":",
    }

    for antigo, novo in substituicoes.items():
        valor = valor.replace(antigo, novo)

    return valor.strip()


def identificar_tipo(indicador: str) -> str:
    """Identifica CVE e utiliza o detector existente para outros IOCs."""
    if re.fullmatch(
        r"CVE-\d{4}-\d{4,7}",
        indicador,
        flags=re.IGNORECASE,
    ):
        return "cve"

    try:
        tipo = detect_ioc_type(indicador)
    except Exception:
        return "unknown"

    if not tipo:
        return "unknown"

    tipo = str(tipo).strip().lower()

    aliases = {
        "ipv4": "ip",
        "ipv6": "ip",
        "sha256": "hash",
        "sha1": "hash",
        "md5": "hash",
        "hostname": "domain",
        "fqdn": "domain",
    }

    return aliases.get(tipo, tipo)


def validar_indicador(indicador: str, tipo: str) -> tuple[bool, str]:
    """Executa validações básicas de formato."""
    if not indicador:
        return False, "Indicador vazio."

    if len(indicador) > 2048:
        return False, "Indicador excede o tamanho permitido."

    if tipo == "ip":
        try:
            ipaddress.ip_address(indicador)
            return True, "Endereço IP válido."
        except ValueError:
            return False, "Endereço IP inválido."

    if tipo == "cve":
        valido = bool(
            re.fullmatch(
                r"CVE-\d{4}-\d{4,7}",
                indicador,
                flags=re.IGNORECASE,
            )
        )
        if valido:
            return True, "Identificador CVE válido."

        return False, "Formato CVE inválido."

    if tipo == "hash":
        hash_limpo = indicador.lower()

        if not re.fullmatch(r"[a-f0-9]+", hash_limpo):
            return False, "O hash contém caracteres inválidos."

        tamanhos = {
            32: "MD5",
            40: "SHA-1",
            64: "SHA-256",
            128: "SHA-512",
        }

        algoritmo = tamanhos.get(len(hash_limpo))

        if algoritmo:
            return True, f"Hash {algoritmo} válido."

        return False, "Tamanho de hash não reconhecido."

    if tipo == "domain":
        dominio = indicador.lower().rstrip(".")

        valido = bool(
            re.fullmatch(
                r"(?=.{1,253}$)"
                r"(?:[a-z0-9]"
                r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z]{2,63}",
                dominio,
                flags=re.IGNORECASE,
            )
        )

        if valido:
            return True, "Domínio com formato válido."

        return False, "Formato de domínio inválido."

    if tipo in {"url", "email"}:
        return True, "Formato reconhecido."

    return False, "Formato não reconhecido automaticamente."


def nivel_triagem(tipo: str, valido: bool) -> str:
    """Define uma prioridade inicial, sem substituir análise externa."""
    if not valido:
        return "Revisar"

    if tipo in {"hash", "url", "ip"}:
        return "Alta"

    if tipo in {"domain", "cve"}:
        return "Média"

    return "Informativa"


def analisar_indicador(valor: str) -> dict:
    indicador_original = valor.strip()
    indicador = normalizar_indicador(indicador_original)
    tipo = identificar_tipo(indicador)
    valido, validacao = validar_indicador(indicador, tipo)
    prioridade = nivel_triagem(tipo, valido)

    recomendacao = RECOMENDACOES.get(
        tipo,
        RECOMENDACOES["unknown"],
    )

    resultado = {
        "timestamp": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "origem": "Threat Intelligence",
        "indicador_original": indicador_original,
        "indicador": indicador,
        "tipo": tipo,
        "tipo_descricao": TIPOS_CONHECIDOS.get(
            tipo,
            tipo.upper(),
        ),
        "valido": valido,
        "validacao": validacao,
        "prioridade": prioridade,
        "fonte_recomendada": recomendacao["fonte"],
        "recomendacao": recomendacao["mensagem"],
    }

    save_history(
        {
            "timestamp": resultado["timestamp"],
            "origem": resultado["origem"],
            "indicador": resultado["indicador"],
            "tipo": resultado["tipo"],
            "valido": resultado["valido"],
            "prioridade": resultado["prioridade"],
        }
    )

    return resultado


def gerar_csv(resultados: list[dict]) -> bytes:
    dataframe = pd.DataFrame(resultados)
    return dataframe.to_csv(
        index=False,
    ).encode("utf-8-sig")


# ------------------------------------------------------------------
# Cabeçalho
# ------------------------------------------------------------------

st.title("🧠 Threat Intelligence v3.9")

st.write(
    "Central de classificação, validação e triagem inicial de "
    "indicadores de comprometimento."
)

st.caption(
    "A classificação local não confirma que um indicador seja "
    "malicioso. Valide os resultados em fontes de inteligência "
    "autorizadas."
)


# ------------------------------------------------------------------
# Área de consulta
# ------------------------------------------------------------------

aba_individual, aba_lote, aba_historico = st.tabs(
    [
        "🔎 Consulta individual",
        "📚 Consulta em lote",
        "🕘 Histórico da sessão",
    ]
)


with aba_individual:
    with st.form(
        "formulario_consulta_individual",
        clear_on_submit=False,
    ):
        query = st.text_input(
            "Indicador, entidade ou CVE",
            placeholder=(
                "Ex.: CVE-2024-1234, 8.8.8.8, example.com "
                "ou hash SHA-256"
            ),
            help=(
                "São aceitos IPs, domínios, URLs, hashes, "
                "e-mails e identificadores CVE."
            ),
        )

        normalizar = st.checkbox(
            "Normalizar indicador ofuscado",
            value=True,
            help=(
                "Converte formatos como hxxps://exemplo[.]com "
                "para https://exemplo.com."
            ),
        )

        consultar = st.form_submit_button(
            "🔍 Classificar indicador",
            type="primary",
            use_container_width=True,
        )

    if consultar:
        valor_consulta = query

        if not normalizar:
            valor_consulta = query.strip()

        if not valor_consulta.strip():
            st.warning("Informe um valor para análise.")
        else:
            with st.spinner("Classificando o indicador..."):
                resultado = analisar_indicador(valor_consulta)

                st.session_state.resultados_threat_intelligence.insert(
                    0,
                    resultado,
                )

            st.subheader("Resultado da triagem")

            coluna_tipo, coluna_validacao, coluna_prioridade = st.columns(3)

            coluna_tipo.metric(
                "Tipo identificado",
                resultado["tipo_descricao"],
            )

            coluna_validacao.metric(
                "Validação",
                "Válido" if resultado["valido"] else "Revisar",
            )

            coluna_prioridade.metric(
                "Prioridade inicial",
                resultado["prioridade"],
            )

            if (
                resultado["indicador_original"]
                != resultado["indicador"]
            ):
                st.info(
                    "Indicador normalizado: "
                    f"`{resultado['indicador']}`"
                )

            if resultado["valido"]:
                st.success(resultado["validacao"])
            else:
                st.warning(resultado["validacao"])

            with st.container(border=True):
                st.markdown(
                    f"**Fonte recomendada:** "
                    f"{resultado['fonte_recomendada']}"
                )
                st.write(resultado["recomendacao"])

            with st.expander("Ver detalhes técnicos"):
                st.json(resultado)


with aba_lote:
    st.write(
        "Informe um indicador por linha. Linhas vazias "
        "e valores duplicados serão ignorados."
    )

    with st.form(
        "formulario_consulta_lote",
        clear_on_submit=False,
    ):
        indicadores_lote = st.text_area(
            "Indicadores",
            height=220,
            placeholder=(
                "8.8.8.8\n"
                "example.com\n"
                "hxxps://example[.]com/login\n"
                "CVE-2024-1234"
            ),
        )

        consultar_lote = st.form_submit_button(
            "📚 Classificar indicadores",
            type="primary",
            use_container_width=True,
        )

    if consultar_lote:
        indicadores = [
            linha.strip()
            for linha in indicadores_lote.splitlines()
            if linha.strip()
        ]

        # Remove duplicados preservando a ordem.
        indicadores = list(dict.fromkeys(indicadores))

        if not indicadores:
            st.warning("Informe pelo menos um indicador.")
        elif len(indicadores) > 100:
            st.error(
                "O limite por consulta é de 100 indicadores."
            )
        else:
            resultados_lote = []

            barra_progresso = st.progress(0)
            status = st.empty()

            for indice, indicador in enumerate(
                indicadores,
                start=1,
            ):
                status.write(
                    f"Analisando {indice} de "
                    f"{len(indicadores)} indicadores..."
                )

                resultado = analisar_indicador(indicador)
                resultados_lote.append(resultado)

                barra_progresso.progress(
                    indice / len(indicadores)
                )

            status.empty()
            barra_progresso.empty()

            st.session_state.resultados_threat_intelligence = (
                resultados_lote
                + st.session_state.resultados_threat_intelligence
            )

            total = len(resultados_lote)
            validos = sum(
                item["valido"]
                for item in resultados_lote
            )
            revisar = total - validos
            alta_prioridade = sum(
                item["prioridade"] == "Alta"
                for item in resultados_lote
            )

            coluna_total, coluna_validos, coluna_revisar, coluna_alta = (
                st.columns(4)
            )

            coluna_total.metric("Total", total)
            coluna_validos.metric("Válidos", validos)
            coluna_revisar.metric("Revisar", revisar)
            coluna_alta.metric(
                "Prioridade alta",
                alta_prioridade,
            )

            dataframe_lote = pd.DataFrame(resultados_lote)

            colunas_exibicao = [
                "indicador",
                "tipo_descricao",
                "valido",
                "prioridade",
                "fonte_recomendada",
                "validacao",
            ]

            st.dataframe(
                dataframe_lote[colunas_exibicao],
                use_container_width=True,
                hide_index=True,
                column_config={
                    "indicador": "Indicador",
                    "tipo_descricao": "Tipo",
                    "valido": st.column_config.CheckboxColumn(
                        "Válido"
                    ),
                    "prioridade": "Prioridade",
                    "fonte_recomendada": "Fonte recomendada",
                    "validacao": "Validação",
                },
            )

            st.download_button(
                "⬇️ Exportar resultados em CSV",
                data=gerar_csv(resultados_lote),
                file_name=(
                    "threat_intelligence_resultados.csv"
                ),
                mime="text/csv",
                use_container_width=True,
            )


with aba_historico:
    resultados_sessao = (
        st.session_state.resultados_threat_intelligence
    )

    if not resultados_sessao:
        st.info(
            "Nenhuma consulta foi realizada nesta sessão."
        )
    else:
        coluna_quantidade, coluna_limpar = st.columns(
            [3, 1]
        )

        coluna_quantidade.metric(
            "Consultas na sessão",
            len(resultados_sessao),
        )

        if coluna_limpar.button(
            "🗑️ Limpar sessão",
            use_container_width=True,
        ):
            st.session_state.resultados_threat_intelligence = []
            st.rerun()

        dataframe_historico = pd.DataFrame(
            resultados_sessao
        )

        colunas_historico = [
            "timestamp",
            "indicador",
            "tipo_descricao",
            "valido",
            "prioridade",
            "fonte_recomendada",
        ]

        st.dataframe(
            dataframe_historico[colunas_historico],
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": "Data UTC",
                "indicador": "Indicador",
                "tipo_descricao": "Tipo",
                "valido": st.column_config.CheckboxColumn(
                    "Válido"
                ),
                "prioridade": "Prioridade",
                "fonte_recomendada": "Fonte recomendada",
            },
        )

        st.download_button(
            "⬇️ Exportar histórico da sessão",
            data=gerar_csv(resultados_sessao),
            file_name=(
                "threat_intelligence_historico_sessao.csv"
            ),
            mime="text/csv",
            use_container_width=True,
        )


st.divider()

st.caption(
    "⚖️ Os resultados constituem uma triagem inicial. "
    "O usuário é responsável por validar as informações e utilizar "
    "a plataforma em conformidade com a legislação e as políticas "
    "de segurança aplicáveis."
)
