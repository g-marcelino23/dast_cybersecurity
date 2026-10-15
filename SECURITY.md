# Política de segurança

Esta aplicação deve ser usada somente contra sistemas próprios, laboratórios ou
alvos para os quais exista autorização explícita.

## Controles do projeto

- O backend escuta em loopback na configuração documentada.
- Alvos públicos exigem HTTPS e prova de propriedade por host exato.
- O scanner não segue redirects durante probes ativos.
- Safe Active executa apenas GET, HEAD e OPTIONS.
- Senhas, tokens, cookies e valores temporários de API não são persistidos.
- `.env`, bancos locais, logs e diretórios de runtime não entram no Git.

## Relato responsável

Não inclua credenciais, tokens, dados pessoais ou evidências de terceiros em um
relato. Registre uma descrição reproduzível com dados sintéticos e informe a
versão afetada.

## Limite de implantação

A versão 0.21.0 é uma aplicação local para demonstração e pesquisa. Exposição em
rede ou operação multiusuário exige, antes, autenticação da plataforma, RBAC,
TLS, fila de jobs persistente, gestão centralizada de segredos, auditoria,
monitoramento e política de backup/restauração.
