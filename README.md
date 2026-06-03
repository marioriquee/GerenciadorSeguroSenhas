# Gerenciador de Senhas do Setor

Aplicacao web interna para cadastro de usuarios e armazenamento de senhas do setor com login, auditoria e criptografia das senhas guardadas.

## Visao Geral

O sistema e uma aplicacao Node.js sem framework externo de backend. O servidor entrega os arquivos da interface, recebe as chamadas da API, valida login e grava os dados no SQL Server ou, para teste local, em arquivo JSON.

Estrutura principal:

```text
.
|-- public/
|   |-- index.html
|   |-- app.js
|   `-- styles.css
|-- scripts/
|   `-- smoke-test.js
|-- src/
|   `-- server.js
|-- .env.example
|-- package.json
`-- README.md
```

Papeis dos arquivos:

- `public/index.html`: tela de login, primeiro acesso, cofre, usuarios e auditoria.
- `public/app.js`: logica da interface e chamadas para a API.
- `public/styles.css`: estilos da aplicacao.
- `src/server.js`: servidor HTTP, API, sessoes, criptografia e persistencia.
- `scripts/smoke-test.js`: teste rapido de login, cofre e criptografia.
- `.env.example`: modelo de configuracao.
- `package.json`: scripts e dependencias Node.js.

Fluxo de dados:

1. O navegador carrega a interface em `public/`.
2. A interface chama rotas `/api/...`.
3. O servidor valida usuario, sessao e permissoes.
4. Senhas de login sao armazenadas como hash `scrypt`.
5. Senhas do cofre sao cifradas com `AES-256-GCM`.
6. O banco armazena usuarios, senhas cifradas e auditoria.

## Recursos

- Login por usuario com cookie HTTP-only.
- Criacao do primeiro administrador protegida por `APP_SETUP_TOKEN`.
- Administradores podem criar e desativar usuarios.
- Cofre compartilhado para o setor.
- Senhas de login com hash `scrypt` e salt individual.
- Senhas cadastradas no cofre com criptografia `AES-256-GCM`.
- Auditoria de login, logout, criacao, atualizacao e exclusao.
- Persistencia em SQL Server usando as tabelas `fatoUsuarios`, `fatoSenhasCofre` e `fatoAuditoria`.
- Modo local em arquivo com `DB_PROVIDER=file`.

## Requisitos

- Node.js 18 ou superior.
- SQL Server acessivel pela rede.
- Login SQL habilitado no SQL Server.
- Tabelas criadas no banco de dados.

## Configuracao

Copie `.env.example` para `.env`:

```powershell
copy .env.example .env
```

Preencha o `.env` com os dados do ambiente. Para SQL Server, os campos principais sao:

```dotenv
DB_PROVIDER=sqlserver
SQLSERVER_HOST=192.168.176.19
SQLSERVER_PORT=1433
SQLSERVER_DATABASE=Senhas
SQLSERVER_USER=usuario_sql
SQLSERVER_PASSWORD=senha_sql
```

Gere uma chave de criptografia para `APP_MASTER_KEY`:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Gere o codigo de instalacao para `APP_SETUP_TOKEN`:

```powershell
node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"
```

`APP_MASTER_KEY` nao deve ser alterada depois que houver senhas salvas. Sem a mesma chave, o sistema nao consegue descriptografar as senhas antigas.

`APP_SETUP_TOKEN` e obrigatorio enquanto nao existir nenhum usuario. Sem esse codigo, ninguem consegue criar o primeiro administrador pela tela publica.

## Banco de Dados

O app espera estas tabelas:

- `dbo.fatoUsuarios`
- `dbo.fatoSenhasCofre`
- `dbo.fatoAuditoria`

Esses nomes podem ser alterados no `.env`:

```dotenv
SQLSERVER_TABLE_USUARIOS=dbo.fatoUsuarios
SQLSERVER_TABLE_SENHAS=dbo.fatoSenhasCofre
SQLSERVER_TABLE_AUDITORIA=dbo.fatoAuditoria
```

As credenciais do banco ficam somente no `.env`. O arquivo `.env` esta no `.gitignore` e nao deve ser enviado ao GitHub.

## Como Rodar

Instale as dependencias:

```powershell
npm.cmd install
```

Inicie o servidor:

```powershell
node src/server.js
```

Ou:

```powershell
npm.cmd start
```

Abra no navegador o endereco configurado no `.env`, por exemplo:

```text
http://192.168.137.59:8090
```

No primeiro acesso, informe nome, usuario, senha e o codigo configurado em `APP_SETUP_TOKEN`.

## Teste

Execute:

```powershell
node scripts/smoke-test.js
```

O teste usa `DB_PROVIDER=file`, cria um banco temporario em arquivo, valida login, cria senha no cofre e confirma que a senha nao aparece em texto puro no arquivo salvo.

## Seguranca Operacional

Para uso real, rode atras de HTTPS ou rede/VPN interna confiavel, proteja o servidor, restrinja permissao ao `.env`, controle backup do banco e mantenha `APP_MASTER_KEY` em local seguro.

Se o sistema estiver publicado com HTTPS, use:

```dotenv
APP_COOKIE_SECURE=true
```

Em ambiente local com HTTP, deixe:

```dotenv
APP_COOKIE_SECURE=false
```
