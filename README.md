# DAST 0.21.0

Plataforma DAST para descoberta e análise dinâmica de aplicações web e APIs autorizadas. A versão 0.21.0 amplia a análise passiva com TLS observado, conteúdo misto e redirects, preservando prova de propriedade, allowlist exata e bloqueio de destinos fora do escopo.

## Capacidades

- navegação de sites e SPAs com Chromium isolado;
- inventário de páginas, formulários, scripts e chamadas fetch/XHR;
- descoberta de endpoints de frontend e backend;
- análise passiva de headers, cookies, CORS, TLS, conteúdo misto, redirects e exposição de servidor;
- scans anônimos ou autenticados por login JSON/formulário, Cookie, Basic, Bearer Token, API Key ou headers personalizados;
- comparação da superfície observada por diferentes perfis;
- probes de autorização GET/HEAD após revisão e confirmação;
- findings classificados por severidade, confiança, CWE e OWASP;
- agrupamento de ocorrências e acompanhamento do estado da correção;
- relatórios JSON, HTML e SARIF.
- presets Discovery, Passive e Custom;
- catálogo de módulos com seleção personalizada;
- progresso por fase e cancelamento seguro.
- importação OpenAPI 3.x e Swagger 2.0 em JSON ou YAML;
- inventário de operações documentadas sem execução automática;
- cadastro manual de endpoints de API com estrutura sanitizada;
- coleta passiva controlada de endpoints manuais GET, HEAD e OPTIONS;
- valores efêmeros de path, query e headers informados somente ao iniciar o scan;
- mascaramento de headers no formulário e persistência apenas dos nomes utilizados;
- resumo visual da cobertura manual com templates, endpoints elegíveis, requests enviados, respostas analisadas e motivos de exclusão;
- análise de CSP permissiva, cache público de possível sessão e exposição de erros técnicos.
- preset Safe Active com confirmação explícita e somente requests GET, HEAD e OPTIONS;
- detecção controlada de Open Redirect, reflexão HTML compatível com XSS, SQL Injection por erro diferencial, Path Traversal por assinatura e métodos HTTP potencialmente perigosos;
- orçamento, atraso entre requests, cancelamento por módulo e registro dos controles ativos no scan.
- cadastro de domínios públicos HTTPS com desafio em `/.well-known/dast-verification.txt`;
- verificação independente de todos os hosts configurados, validade de 30 dias e bloqueio do scan quando pendente ou expirada;
- allowlist de hosts exatos, conexão com DNS fixado, bloqueio de resolução privada/mista e redirects desabilitados.

## Limites atuais

Esta versão aceita `localhost`, loopback, redes privadas RFC1918 e domínios públicos HTTPS cuja propriedade tenha sido verificada. IPs públicos diretos, curingas de subdomínio, resolução DNS privada/mista e hosts não cadastrados continuam bloqueados. Cada host de frontend e API precisa responder ao desafio; a autorização expira após 30 dias.

Os presets disponíveis são `Discovery`, `Passive`, `Safe Active` e `Custom`. Formulários são inventariados, mas não submetidos. Endpoints manuais GET/HEAD/OPTIONS podem receber valores temporários de path, query e headers no início do scan, com orçamento e atraso configuráveis. Esses valores existem somente em memória; banco, endpoints, findings e relatórios recebem apenas templates e nomes sanitizados. Queries sem valor usam o marcador `dast`. Templates autenticados sem sessão disponível e métodos mutáveis permanecem somente no inventário. O Safe Active exige confirmação explícita, não segue redirects e nunca executa métodos mutáveis. Testes de autorização continuam limitados a GET/HEAD aprovados pelo usuário.

A ausência de findings não comprova que a aplicação está segura. O resultado cobre somente os recursos alcançados e os módulos executados.

## Resultados e relatórios

Cada scan apresenta no site:

- resumo por severidade;
- issues únicos, ocorrências e endpoints afetados;
- páginas, APIs e formulários descobertos;
- vulnerabilidades, possíveis vulnerabilidades, configurações inseguras e informações;
- evidências sanitizadas e recomendações;
- estado do finding: aberta, confirmada, em análise, em correção, resolvida, risco aceito, falso positivo ou reaberta;
- dados sensíveis observados como metadados, separados das vulnerabilidades;
- limitações e cobertura do scan.

Os relatórios podem ser exportados em JSON, HTML e SARIF 2.1.0.

## Arquitetura

```text
frontend (React + TypeScript + Vite, :5174)
    │ REST/JSON
backend (FastAPI + Pydantic, :8000)
    ├── api/          endpoints e contratos
    ├── services/     scans, autenticação e autorização
    ├── crawler/      Chromium, escopo e inventário
    ├── scanner/      coletor HTTP e módulos
    ├── privacy/      classificação sanitizada
    ├── core/         configuração, escopo e segredos
    ├── models/       entidades SQLAlchemy
    └── database/     sessão e migrações Alembic
             │
             └── PostgreSQL
```

Cada scan autenticado recebe um `BrowserContext` exclusivo. Tokens, cookies e senhas não são incluídos nas respostas da API nem nos relatórios.

## Política de alvo

São permitidos:

- `localhost`, `127.0.0.1` e `::1`;
- `10.0.0.0/8`;
- `172.16.0.0/12`;
- `192.168.0.0/16`.
- domínios públicos HTTPS verificados, somente pelos hosts exatos cadastrados.

A política é aplicada ao cadastro, navegação, redirects, autenticação e requests do scanner. Hostnames são resolvidos e fixados ao endereço validado para reduzir risco de SSRF e DNS rebinding.

Use a ferramenta somente em aplicações próprias, laboratórios ou sistemas para os quais exista autorização explícita.

## Autenticação e autorização

Um perfil de acesso pertence a uma aplicação e possui nome e role livres. Os tipos atuais são `NONE`, `BEARER_LOGIN`, `COOKIE_LOGIN`, `FORM_LOGIN`, `BASIC`, `BEARER_TOKEN`, `API_KEY` e `CUSTOM_HEADERS`.

O login aceita body JSON ou formulário configurável com `{{username}}` e `{{password}}`. Perfis diretos usam templates de headers com `{{secret}}`; senhas, tokens e chaves são fornecidos somente na validação e mantidos em sessão temporária para o próximo scan. MFA configurável também é suportado. O identificador pode ser protegido com Fernet por meio de `DAST_SECRET_KEY`.

Testes de autorização comparam um baseline legítimo com a resposta entregue a outro perfil. HTTP 200 isoladamente não confirma vulnerabilidade. Métodos mutáveis são inventariados, mas não executados. Candidatos permanecem `SUGGESTED` e regras precisam estar `APPROVED`.

## Instalação

Requisitos: Python 3.11–3.13, Node.js 20+, PostgreSQL 15+ e Chromium do Playwright.
Python 3.14 ainda não é suportado pela stack assíncrona usada nos testes no Windows.

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".\backend[dev]"
.venv\Scripts\python.exe -m playwright install chromium
npm.cmd install --prefix frontend
python scripts\setup_env.py
docker compose up -d postgres
.venv\Scripts\python.exe -m alembic -c backend\alembic.ini upgrade head
```

Backend:

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
npm.cmd run dev --prefix frontend
```

Interface: `http://localhost:5174`

API: `http://localhost:8000`

Documentação: `http://localhost:8000/docs`

## Validação

```powershell
.venv\Scripts\python.exe -m pytest backend\tests -q
.venv\Scripts\python.exe -m ruff check backend\app backend\tests
.venv\Scripts\python.exe -m mypy backend\app
npm.cmd test --prefix frontend
npm.cmd run typecheck --prefix frontend
npm.cmd run lint --prefix frontend
npm.cmd run build --prefix frontend
```

No Windows, `scripts\validate.ps1` executa toda essa sequência. O workflow
`.github/workflows/quality.yml` repete a validação no GitHub Actions com Python
3.11, 3.12 e 3.13 e Node.js 20.

### Laboratório local do Safe Active

O projeto inclui um alvo genérico deliberadamente vulnerável, com dados apenas sintéticos,
para validar os módulos ativos ponta a ponta:

```powershell
.venv\Scripts\python.exe scripts\safe_active_lab.py
```

Cadastre `http://127.0.0.1:8775` como alvo `FIXTURE` e execute o preset `Safe Active`.
O laboratório cobre CWE-22, CWE-79, CWE-89, CWE-601 e CWE-749, registra contadores de
métodos em `/__metrics` e rejeita POST, PUT, PATCH e DELETE. Não exponha esse servidor à rede.

## Próximas etapas

- aplicações com múltiplos componentes;
- comparação diferencial de conteúdo e status com tolerância configurável;
- autenticação OAuth/OIDC;
- comparação automática entre scans;
