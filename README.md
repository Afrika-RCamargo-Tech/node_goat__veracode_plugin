# 🐐 Node Goat - Aplicação Vulnerável para Testes Veracode

[![Security: Intentionally Vulnerable](https://img.shields.io/badge/security-intentionally%20vulnerable-red.svg)](https://github.com/Afrika-RCamargo-Tech/node_goat__veracode_plugin)
[![Node.js](https://img.shields.io/badge/node.js-14.x%20|%2016.x%20|%2018.x-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ⚠️ AVISO IMPORTANTE

**Esta aplicação contém vulnerabilidades de segurança INTENCIONAIS para fins educacionais e de teste com ferramentas SAST e SCA como Veracode. NUNCA use este código em produção!**

## 📖 Sobre o Projeto

Node Goat é uma aplicação Node.js deliberadamente vulnerável, desenvolvida para testar e demonstrar capacidades de ferramentas de segurança como:
- **SAST** (Static Application Security Testing)
- **SCA** (Software Composition Analysis)
- **Pipeline de CI/CD com Veracode**

A aplicação está completamente em **português brasileiro (pt-BR)** e contém documentação detalhada de cada vulnerabilidade com seus respectivos códigos CWE.

## 🎯 Objetivos

- Demonstrar vulnerabilidades comuns em aplicações Node.js
- Testar integração do Veracode em pipelines de CI/CD
- Fornecer material educacional sobre segurança de aplicações
- Validar ferramentas SAST e SCA em cenários reais

## 🚨 Vulnerabilidades Implementadas

A aplicação contém as seguintes vulnerabilidades intencionais:

| # | Vulnerabilidade | CWE | Severidade | Tipo |
|---|----------------|-----|-----------|------|
| 1 | SQL Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | 🔴 Crítica | SAST |
| 2 | Cross-Site Scripting (XSS) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | 🟠 Alta | SAST |
| 3 | Command Injection | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | 🔴 Crítica | SAST |
| 4 | Path Traversal | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | 🟠 Alta | SAST |
| 5 | Hardcoded Credentials | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | 🔴 Crítica | SAST |
| 6 | Insecure Deserialization | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | 🔴 Crítica | SAST |
| 7 | XML External Entity (XXE) | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | 🟠 Alta | SAST |
| 8 | Server-Side Request Forgery (SSRF) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | 🟠 Alta | SAST |
| 9 | Componentes com Vulnerabilidades Conhecidas | [CWE-1035](https://cwe.mitre.org/data/definitions/1035.html) | 🟡 Variável | SCA |

Para detalhes completos sobre cada vulnerabilidade, consulte [VULNERABILIDADES.md](./VULNERABILIDADES.md).

## 🛠️ Tecnologias Utilizadas

- **Node.js** - Runtime JavaScript
- **Express** - Framework web
- **SQLite3** - Banco de dados
- **EJS** - Template engine
- **Bibliotecas vulneráveis intencionalmente** - Para testes de SCA

## 📋 Pré-requisitos

- Node.js 14.x ou superior
- npm ou yarn

## 🚀 Instalação e Execução

### 1. Clone o repositório

```bash
git clone https://github.com/Afrika-RCamargo-Tech/node_goat__veracode_plugin.git
cd node_goat__veracode_plugin
```

### 2. Instale as dependências

```bash
npm install
```

### 3. Execute a aplicação

```bash
npm start
```

A aplicação estará disponível em: **http://localhost:3000**

### 4. Modo de desenvolvimento (com auto-reload)

```bash
npm run dev
```

## 🔍 Estrutura do Projeto

```
node_goat__veracode_plugin/
├── app.js                    # Aplicação principal com vulnerabilidades
├── package.json              # Dependências (incluindo vulneráveis)
├── VULNERABILIDADES.md       # Documentação detalhada das vulnerabilidades
├── README.md                 # Este arquivo
└── .gitignore               # Arquivos ignorados pelo Git
```

## 📚 Documentação

### Funcionalidades Vulneráveis

Acesse `http://localhost:3000` para ver todas as funcionalidades:

1. **🔍 Busca de Usuários** - SQL Injection (CWE-89)
2. **💬 Comentários** - XSS (CWE-79)
3. **⚙️ Executar Comando** - Command Injection (CWE-78)
4. **📁 Download de Arquivo** - Path Traversal (CWE-22)
5. **🔧 Configuração** - Hardcoded Credentials (CWE-798)
6. **🍪 Gerenciar Cookie** - Insecure Deserialization (CWE-502)
7. **📄 Processar XML** - XXE (CWE-611)
8. **🌐 Proxy Request** - SSRF (CWE-918)

### Documentação Completa

Consulte [VULNERABILIDADES.md](./VULNERABILIDADES.md) para:
- Descrição detalhada de cada vulnerabilidade
- Localização exata no código
- Exemplos de exploração
- Código CWE associado
- Impacto e severidade
- Como corrigir cada vulnerabilidade

## 🧪 Testando com Veracode

### SAST (Static Analysis)

```bash
# Upload do código para análise estática
veracode upload --app "Node Goat" --file .
```

### SCA (Software Composition Analysis)

```bash
# Análise de dependências vulneráveis
veracode sca scan
```

### Pipeline CI/CD

Exemplo de integração no GitHub Actions:

```yaml
name: Veracode Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Veracode Upload and Scan
        uses: veracode/veracode-uploadandscan-action@master
        with:
          appname: 'Node Goat'
          createprofile: true
          version: '${{ github.run_id }}'
          filepath: '.'
          vid: '${{ secrets.VERACODE_API_ID }}'
          vkey: '${{ secrets.VERACODE_API_KEY }}'
```

## 🎓 Uso Educacional

Este projeto é ideal para:

- **Treinamentos de Segurança** - Demonstrar vulnerabilidades reais
- **Testes de Ferramentas** - Validar capacidades de SAST/SCA
- **Workshops** - Ensinar práticas seguras de desenvolvimento
- **CTF/Capture The Flag** - Ambiente de prática controlado
- **CI/CD Security** - Integrar segurança em pipelines

## 🧪 Exemplos de Testes

### SQL Injection

```bash
# Teste básico
curl -X POST http://localhost:3000/buscar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=' OR '1'='1"
```

### XSS (Cross-Site Scripting)

```bash
# Injeção de script
curl -X POST http://localhost:3000/comentario \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comentario=<script>alert('XSS')</script>"
```

### Command Injection

```bash
# Execução de múltiplos comandos
curl -X POST http://localhost:3000/executar \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comando=ls; whoami; pwd"
```

### Path Traversal

```bash
# Tentativa de ler /etc/passwd
curl -X POST http://localhost:3000/arquivo \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "filename=../../../etc/passwd"
```

## 🛡️ Ferramentas de Teste Recomendadas

### SAST
- **Veracode Static Analysis** ⭐
- SonarQube
- Checkmarx
- Fortify

### SCA
- **Veracode SCA** ⭐
- Snyk
- WhiteSource
- OWASP Dependency-Check

### DAST
- Burp Suite
- OWASP ZAP
- Acunetix

## 📊 Resultados Esperados

Ao escanear esta aplicação com ferramentas SAST/SCA, você deve encontrar:

- ✅ 8+ vulnerabilidades SAST de alta/crítica severidade
- ✅ 5+ vulnerabilidades em dependências (SCA)
- ✅ Múltiplos pontos de injeção
- ✅ Credenciais hardcoded
- ✅ Componentes desatualizados

## 🤝 Contribuindo

Contribuições são bem-vindas! Se você deseja adicionar novas vulnerabilidades ou melhorar a documentação:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-vulnerabilidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova vulnerabilidade XYZ'`)
4. Push para a branch (`git push origin feature/nova-vulnerabilidade`)
5. Abra um Pull Request

## 📖 Recursos Adicionais

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Veracode Documentation](https://docs.veracode.com/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)

## ⚖️ Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🚨 Disclaimer

**IMPORTANTE:** Este software é fornecido apenas para fins educacionais e de teste em ambientes controlados. Os autores e contribuidores não se responsabilizam por qualquer uso indevido ou danos causados por este código.

- ❌ NÃO use em produção
- ❌ NÃO exponha na internet pública
- ✅ Use apenas em ambientes de teste isolados
- ✅ Use apenas com autorização apropriada
- ✅ Use para fins educacionais e de teste

## 👥 Autores

- **Afrika-RCamargo-Tech**

## 📞 Contato

Para questões ou sugestões, abra uma [issue](https://github.com/Afrika-RCamargo-Tech/node_goat__veracode_plugin/issues) no GitHub.

---

**⚠️ Lembre-se: Esta aplicação é INTENCIONALMENTE VULNERÁVEL. Use com responsabilidade!**