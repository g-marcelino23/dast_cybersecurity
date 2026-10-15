# Checklist de entrega

## Qualidade automatizada

- [x] `scripts/validate.ps1` termina sem erros.
- [x] Os 189 testes backend passam em uma versão suportada do Python.
- [x] Os testes frontend passam.
- [x] Ruff, mypy, ESLint e TypeScript não reportam erros.
- [x] O build Vite é gerado.
- [x] `npm audit --omit=dev` não reporta vulnerabilidades.
- [ ] O workflow `Quality` passa no GitHub Actions.

## Banco e execução integrada

- [x] PostgreSQL isolado está saudável em loopback.
- [x] `alembic upgrade head` conclui e chega à revisão `0018_public_target_verification`.
- [x] Backend responde `200` em `/health`.
- [x] Frontend responde `200` em `http://localhost:5174`.
- [x] É possível cadastrar um alvo local autorizado.
- [x] Um scan Safe Active termina e produz inventário e findings.
- [x] O laboratório `scripts/safe_active_lab.py` confirma os cinco módulos ativos.
- [x] O laboratório confirma que POST, PUT, PATCH e DELETE não foram executados.
- [x] Cancelamento e exportação JSON, HTML e SARIF possuem cobertura automatizada.

## Segurança e privacidade

- [ ] Nenhum segredo real está no Git ou nos relatórios.
- [x] `.env`, bancos, logs, runtime e `node_modules` continuam ignorados.
- [x] Um domínio público não verificado permanece bloqueado.
- [x] Redirect externo e resolução privada/mista permanecem bloqueados.
- [x] Evidências e erros não expõem tokens, cookies ou valores temporários.

## Entrega

- [x] README corresponde às funcionalidades atuais.
- [ ] O repositório está limpo e o commit de entrega foi revisado.
- [x] A versão está alinhada no backend, frontend e interface.
- [ ] A tag `v0.22.0` aponta para o commit aprovado.
- [ ] Uma cópia do banco de demonstração, se usada, contém somente dados sintéticos.
