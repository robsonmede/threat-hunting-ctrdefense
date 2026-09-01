
## `DISCLAIMER.md`

```markdown
# Aviso Legal e Termos de Uso

## 1. Finalidade

O Cyber Threat Research é uma ferramenta destinada a fins educacionais, acadêmicos, defensivos e de pesquisa em segurança da informação.

A aplicação pode realizar consultas a serviços externos de Threat Intelligence, reputação de IPs, análise de indicadores de comprometimento e verificação de exposição de dados.

---

## 2. Uso autorizado

O usuário é exclusivamente responsável por utilizar a ferramenta de forma legal, ética e autorizada.

A ferramenta deve ser utilizada somente:

- Em sistemas, redes e ativos pertencentes ao usuário;
- Com autorização expressa do proprietário do ambiente;
- Em atividades de resposta a incidentes;
- Em testes de segurança autorizados;
- Em laboratórios controlados;
- Em estudos acadêmicos;
- Em atividades de investigação defensiva e conformidade.

---

## 3. Proibição de uso indevido

É proibido utilizar este projeto para:

- Acessar sistemas sem autorização;
- Invadir, degradar ou interromper serviços;
- Praticar exploração ofensiva não autorizada;
- Realizar varreduras indevidas;
- Coletar ou expor dados pessoais sem base legal;
- Monitorar terceiros de forma não autorizada;
- Distribuir malware;
- Realizar phishing, fraude ou engenharia social;
- Burlar autenticação, controles de acesso ou mecanismos de segurança;
- Violar limites, políticas ou termos das APIs utilizadas;
- Praticar qualquer atividade contrária à legislação aplicável.

---

## 4. Responsabilidade do usuário

O usuário é responsável por:

- Obter as autorizações necessárias antes de realizar consultas;
- Respeitar a legislação de proteção de dados;
- Respeitar os termos de uso dos serviços integrados;
- Proteger suas chaves de API;
- Não publicar tokens, credenciais ou dados sensíveis;
- Validar os resultados antes de tomar decisões;
- Evitar o envio de informações confidenciais a serviços externos;
- Controlar o acesso à aplicação e aos relatórios gerados.

---

## 5. Dados enviados a serviços externos

Ao utilizar integrações como VirusTotal, AbuseIPDB, urlscan.io, Shodan ou outros serviços, os dados informados podem ser transmitidos aos respectivos provedores.

Antes de realizar uma consulta, o usuário deve verificar:

- A política de privacidade do serviço;
- Os termos de uso da API;
- As regras de retenção e compartilhamento de dados;
- As limitações de uso comercial ou gratuito;
- A existência de requisitos de consentimento ou base legal.

Não envie informações confidenciais, credenciais, documentos privados ou dados pessoais sem autorização apropriada.

---

## 6. Ausência de garantia

O projeto é fornecido no estado em que se encontra, sem garantias expressas ou implícitas.

Os resultados apresentados podem:

- Estar incompletos;
- Conter falsos positivos;
- Conter falsos negativos;
- Estar desatualizados;
- Depender da disponibilidade dos serviços externos;
- Ser afetados por limites, alterações ou indisponibilidade das APIs.

Nenhum resultado deve ser considerado, isoladamente, uma confirmação definitiva de comprometimento, fraude, invasão ou atividade maliciosa.

---

## 7. Limitação de responsabilidade

Os autores, colaboradores e mantenedores do projeto não serão responsáveis por:

- Danos diretos ou indiretos;
- Perda de dados;
- Interrupção de serviços;
- Exposição indevida de informações;
- Uso incorreto da aplicação;
- Violações de leis ou contratos;
- Suspensão ou bloqueio de contas de API;
- Consequências decorrentes de decisões tomadas com base nos resultados;
- Atividades realizadas por terceiros utilizando este código.

A responsabilidade pela instalação, configuração, operação e uso da ferramenta é exclusivamente do usuário.

---

## 8. Proteção de credenciais

O usuário deve:

- Manter as chaves de API fora do código-fonte;
- Utilizar variáveis de ambiente ou secrets;
- Evitar publicar arquivos `.env`;
- Evitar compartilhar capturas de tela com tokens;
- Revogar imediatamente credenciais expostas;
- Utilizar permissões mínimas sempre que possível.

Exemplo de arquivos que não devem ser publicados:

```text
.env
.streamlit/secrets.toml
config.json
credentials.json
