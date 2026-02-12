/**
 * APLICAÇÃO NODE.JS VULNERÁVEL - PARA TESTES DE SEGURANÇA
 * 
 * ATENÇÃO: Esta aplicação contém vulnerabilidades INTENCIONAIS
 * para fins de teste com ferramentas SAST e SCA como Veracode.
 * NÃO USE EM PRODUÇÃO!
 */

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const libxmljs = require('libxmljs2');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const dns = require('dns');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;

// CORREÇÃO CWE-798: Credenciais DEVEM ser configuradas via variáveis de ambiente
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const API_KEY = process.env.API_KEY;

if (!DB_USER || !DB_PASSWORD || !API_KEY) {
  console.warn('AVISO: Variáveis de ambiente DB_USER, DB_PASSWORD e API_KEY não estão configuradas.');
}

// Função utilitária centralizada para escape de HTML (previne XSS)
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(fileUpload());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));

// Banco de dados SQLite
const db = new sqlite3.Database(':memory:');

// Inicializar banco de dados
db.serialize(() => {
  db.run("CREATE TABLE usuarios (id INTEGER PRIMARY KEY, nome TEXT, email TEXT, senha TEXT, perfil TEXT)");
  db.run("CREATE TABLE produtos (id INTEGER PRIMARY KEY, nome TEXT, preco REAL, descricao TEXT)");
  db.run("CREATE TABLE pedidos (id INTEGER PRIMARY KEY, usuario_id INTEGER, produto_id INTEGER, quantidade INTEGER)");
  
  // Dados de exemplo
  db.run("INSERT INTO usuarios (nome, email, senha, perfil) VALUES ('Admin', 'admin@exemplo.com', 'admin123', 'administrador')");
  db.run("INSERT INTO usuarios (nome, email, senha, perfil) VALUES ('João Silva', 'joao@exemplo.com', 'senha123', 'usuario')");
  db.run("INSERT INTO produtos (nome, preco, descricao) VALUES ('Notebook', 2500.00, 'Notebook Intel i5')");
  db.run("INSERT INTO produtos (nome, preco, descricao) VALUES ('Mouse', 50.00, 'Mouse sem fio')");
});

// Página inicial
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Aplicação Vulnerável - Node.js</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #d32f2f; }
        .warning { background: #fff3cd; padding: 20px; border-left: 4px solid #ffc107; margin: 20px 0; }
        .menu { list-style: none; padding: 0; }
        .menu li { margin: 10px 0; }
        .menu a { color: #1976d2; text-decoration: none; font-size: 18px; }
        .menu a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <h1>⚠️ Aplicação Node.js Vulnerável</h1>
      <div class="warning">
        <strong>AVISO:</strong> Esta aplicação contém vulnerabilidades de segurança INTENCIONAIS 
        para fins de teste com ferramentas SAST e SCA (como Veracode).
        <br><strong>NÃO USE EM PRODUÇÃO!</strong>
      </div>
      
      <h2>Funcionalidades Vulneráveis:</h2>
      <ul class="menu">
        <li><a href="/buscar">🔍 Busca de Usuários (SQL Injection - CWE-89)</a></li>
        <li><a href="/comentario">💬 Comentários (XSS - CWE-79)</a></li>
        <li><a href="/executar">⚙️ Executar Comando (Command Injection - CWE-78)</a></li>
        <li><a href="/arquivo">📁 Download de Arquivo (Path Traversal - CWE-22)</a></li>
        <li><a href="/config">🔧 Configuração (Hardcoded Credentials - CWE-798)</a></li>
        <li><a href="/cookie">🍪 Gerenciar Cookie (Insecure Deserialization - CWE-502)</a></li>
        <li><a href="/xml">📄 Processar XML (XXE - CWE-611)</a></li>
        <li><a href="/proxy">🌐 Proxy Request (SSRF - CWE-918)</a></li>
      </ul>
      
      <p><a href="/vulnerabilidades">📚 Documentação das Vulnerabilidades</a></p>
    </body>
    </html>
  `);
});

// VULNERABILIDADE 1: SQL Injection (CWE-89)
app.get('/buscar', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Busca de Usuários</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        input, button { padding: 10px; margin: 5px; font-size: 16px; }
      </style>
    </head>
    <body>
      <h1>Buscar Usuário</h1>
      <form action="/buscar" method="POST">
        <input type="text" name="email" placeholder="Digite o email do usuário" required>
        <button type="submit">Buscar</button>
      </form>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.post('/buscar', (req, res) => {
  const email = req.body.email;

  // Validação de formato de email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || typeof email !== 'string' || !emailRegex.test(email)) {
    return res.status(400).send('<h1>Erro</h1><p>Formato de email inválido.</p><a href="/buscar">Voltar</a>');
  }

  // CORREÇÃO CWE-89: Prepared statement com parameterized query
  const query = 'SELECT * FROM usuarios WHERE email = ?';

  db.all(query, [email], (err, rows) => {
    if (err) {
      res.send(`<h1>Erro</h1><p>Erro interno ao buscar.</p><a href="/">Voltar</a>`);
    } else {
      let html = '<h1>Resultados da Busca</h1>';
      if (rows.length > 0) {
        html += '<ul>';
        rows.forEach(row => {
          html += `<li>Nome: ${escapeHtml(row.nome)}, Email: ${escapeHtml(row.email)}, Perfil: ${escapeHtml(row.perfil)}</li>`;
        });
        html += '</ul>';
      } else {
        html += '<p>Nenhum usuário encontrado.</p>';
      }
      html += '<p><a href="/buscar">← Voltar</a></p>';
      res.send(html);
    }
  });
});

// VULNERABILIDADE 2: Cross-Site Scripting (XSS) (CWE-79)
app.get('/comentario', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Comentários</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        textarea { width: 100%; max-width: 500px; height: 100px; padding: 10px; }
        button { padding: 10px 20px; font-size: 16px; }
      </style>
    </head>
    <body>
      <h1>Deixe seu Comentário</h1>
      <form action="/comentario" method="POST">
        <textarea name="comentario" placeholder="Digite seu comentário aqui..." required></textarea><br>
        <button type="submit">Enviar</button>
      </form>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.post('/comentario', (req, res) => {
  const comentario = req.body.comentario;

  // Validação da entrada
  if (!comentario || typeof comentario !== 'string') {
    return res.status(400).send('<h1>Erro</h1><p>Comentário inválido.</p><a href="/comentario">Voltar</a>');
  }

  // Limitar tamanho do comentário
  const comentarioLimitado = comentario.substring(0, 1000);

  // CORREÇÃO CWE-79: Escape de HTML para prevenir XSS
  res.send(`
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Comentário Enviado</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
      </style>
    </head>
    <body>
      <h1>Comentário Recebido</h1>
      <p>Você comentou:</p>
      <div style="border: 1px solid #ccc; padding: 10px; background: #f9f9f9;">
        ${escapeHtml(comentarioLimitado)}
      </div>
      <p><a href="/comentario">← Voltar</a></p>
    </body>
    </html>
  `);
});

// VULNERABILIDADE 3: Command Injection (CWE-78)
app.get('/executar', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Executar Comando</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        input, button { padding: 10px; margin: 5px; font-size: 16px; }
      </style>
    </head>
    <body>
      <h1>Executar Comando de Sistema</h1>
      <form action="/executar" method="POST">
        <input type="text" name="comando" placeholder="Digite o comando (ex: ls, pwd)" required>
        <button type="submit">Executar</button>
      </form>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.post('/executar', (req, res) => {
  const comando = req.body.comando;

  // CORREÇÃO: Whitelist de comandos seguros permitidos
  const allowedCommands = ['ls', 'pwd', 'whoami', 'date', 'hostname', 'uptime'];

  // Validação centralizada da entrada
  if (!comando || typeof comando !== 'string') {
    return res.status(400).send('<h1>Erro</h1><p>Comando inválido.</p><a href="/executar">Voltar</a>');
  }

  // Sanitização: rejeitar caracteres perigosos de shell (metacaracteres)
  const dangerousChars = /[;&|`$(){}\[\]!#~<>"'\\\n\r]/;
  if (dangerousChars.test(comando)) {
    return res.status(400).send('<h1>Erro</h1><p>Caracteres não permitidos detectados no comando.</p><a href="/executar">Voltar</a>');
  }

  // Separar comando e argumentos como array (evita injeção via shell)
  const parts = comando.trim().split(/\s+/);
  const cmd = parts[0];
  const args = parts.slice(1);

  // Validar se o comando está na whitelist
  if (!allowedCommands.includes(cmd)) {
    return res.status(403).send(
      `<h1>Erro</h1><p>Comando não permitido: ${cmd}</p><p>Comandos permitidos: ${allowedCommands.join(', ')}</p><a href="/executar">Voltar</a>`
    );
  }

  // Validar argumentos: permitir apenas caracteres alfanuméricos, pontos, hífens e barras
  const safeArgPattern = /^[a-zA-Z0-9._\-\/]+$/;
  for (const arg of args) {
    if (!safeArgPattern.test(arg)) {
      return res.status(400).send('<h1>Erro</h1><p>Argumento inválido detectado.</p><a href="/executar">Voltar</a>');
    }
  }

  // Usar execFile (versão segura) que NÃO invoca o shell e recebe argumentos como array
  execFile(cmd, args, { timeout: 5000 }, (error, stdout, stderr) => {
    let output = '';
    if (error) {
      output = `Erro: ${error.message}`;
    } else if (stderr) {
      output = `Stderr: ${stderr}`;
    } else {
      output = stdout;
    }

    // Escapar saída para prevenir XSS no resultado
    const escapeHtml = (str) => str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    res.send(`
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Resultado do Comando</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          pre { background: #f4f4f4; padding: 15px; border: 1px solid #ddd; }
        </style>
      </head>
      <body>
        <h1>Resultado do Comando</h1>
        <pre>${escapeHtml(output)}</pre>
        <p><a href="/executar">← Voltar</a></p>
      </body>
      </html>
    `);
  });
});

// VULNERABILIDADE 4: Path Traversal (CWE-22)
app.get('/arquivo', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Download de Arquivo</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        input, button { padding: 10px; margin: 5px; font-size: 16px; }
      </style>
    </head>
    <body>
      <h1>Download de Arquivo</h1>
      <form action="/arquivo" method="POST">
        <input type="text" name="filename" placeholder="Nome do arquivo" required>
        <button type="submit">Download</button>
      </form>
      <p>Exemplos: package.json, README.md</p>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.post('/arquivo', (req, res) => {
  const filename = req.body.filename;

  // Validação da entrada
  if (!filename || typeof filename !== 'string') {
    return res.status(400).send('<h1>Erro</h1><p>Nome de arquivo inválido.</p><a href="/arquivo">Voltar</a>');
  }

  // CORREÇÃO CWE-22: Whitelist de arquivos permitidos
  const allowedFiles = ['package.json', 'README.md', 'LICENSE', 'VULNERABILIDADES.md', 'CVE_CONFIRMADOS.md', 'GUIA_DE_TESTES.md', 'RELATORIO_TESTES.md'];

  // Rejeitar path traversal: bloquear .., barras absolutas, e caracteres perigosos
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\') || filename.startsWith('.')) {
    return res.status(403).send('<h1>Erro</h1><p>Caracteres de caminho não permitidos.</p><a href="/arquivo">Voltar</a>');
  }

  // Verificar se o arquivo está na whitelist
  if (!allowedFiles.includes(filename)) {
    return res.status(403).send(
      `<h1>Erro</h1><p>Arquivo não permitido.</p><p>Arquivos disponíveis: ${allowedFiles.join(', ')}</p><a href="/arquivo">Voltar</a>`
    );
  }

  // Resolver caminho e verificar que está dentro do diretório permitido
  const baseDir = path.resolve(__dirname);
  const filepath = path.resolve(path.join(__dirname, filename));

  if (!filepath.startsWith(baseDir + path.sep) && filepath !== baseDir) {
    return res.status(403).send('<h1>Erro</h1><p>Acesso negado.</p><a href="/arquivo">Voltar</a>');
  }

  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) {
      res.send(`<h1>Erro</h1><p>Arquivo não encontrado.</p><a href="/arquivo">Voltar</a>`);
    } else {
      res.send(`
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Conteúdo do Arquivo</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            pre { background: #f4f4f4; padding: 15px; border: 1px solid #ddd; white-space: pre-wrap; }
          </style>
        </head>
        <body>
          <h1>Conteúdo: ${escapeHtml(filename)}</h1>
          <pre>${escapeHtml(data)}</pre>
          <p><a href="/arquivo">← Voltar</a></p>
        </body>
        </html>
      `);
    }
  });
});

// CORREÇÃO CWE-798/CWE-312: Não expor credenciais em texto plano
app.get('/config', (req, res) => {
  // Mascarar valores sensíveis para exibição
  const maskValue = (val) => val ? val.substring(0, 2) + '***' + val.substring(val.length - 2) : '(não configurado)';

  res.send(`
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Configuração</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .config { background: #f4f4f4; padding: 15px; border: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <h1>Configurações do Sistema</h1>
      <div class="config">
        <p><strong>Usuário do Banco:</strong> ${escapeHtml(maskValue(DB_USER))}</p>
        <p><strong>Senha do Banco:</strong> ${escapeHtml(maskValue(DB_PASSWORD))}</p>
        <p><strong>API Key:</strong> ${escapeHtml(maskValue(API_KEY))}</p>
      </div>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

// VULNERABILIDADE 6: Insecure Deserialization (CWE-502)
app.get('/cookie', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Gerenciar Cookie</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        input, button { padding: 10px; margin: 5px; font-size: 16px; }
      </style>
    </head>
    <body>
      <h1>Gerenciar Cookie de Usuário</h1>
      <form action="/cookie" method="POST">
        <input type="text" name="userData" placeholder='{"nome":"João","admin":false}' style="width: 400px;" required>
        <button type="submit">Salvar Cookie</button>
      </form>
      <p><a href="/cookie/ler">Ver Cookie Atual</a></p>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.post('/cookie', (req, res) => {
  const userData = req.body.userData;

  // Validação da entrada
  if (!userData || typeof userData !== 'string') {
    return res.status(400).send('<h1>Erro</h1><p>Dados inválidos.</p><a href="/cookie">Voltar</a>');
  }

  // CORREÇÃO CWE-502: Usar JSON.parse seguro em vez de node-serialize
  let parsed;
  try {
    parsed = JSON.parse(userData);
  } catch (e) {
    return res.status(400).send('<h1>Erro</h1><p>JSON inválido.</p><a href="/cookie">Voltar</a>');
  }

  // Schema validation: permitir apenas campos esperados com tipos seguros
  const allowedKeys = ['nome', 'admin', 'email', 'perfil'];
  const sanitized = {};
  for (const key of allowedKeys) {
    if (parsed[key] !== undefined) {
      if (typeof parsed[key] === 'string' || typeof parsed[key] === 'boolean' || typeof parsed[key] === 'number') {
        sanitized[key] = parsed[key];
      }
    }
  }

  // Usar JSON seguro para o cookie (sem serialização insegura)
  const cookieValue = Buffer.from(JSON.stringify(sanitized)).toString('base64');
  res.cookie('userData', cookieValue, { httpOnly: true, sameSite: 'strict' });

  res.send(`
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Cookie Salvo</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
      </style>
    </head>
    <body>
      <h1>Cookie Salvo com Sucesso!</h1>
      <p><a href="/cookie">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.get('/cookie/ler', (req, res) => {
  const cookie = req.cookies.userData;

  if (cookie) {
    // CORREÇÃO CWE-502: Deserialização segura usando JSON.parse em vez de node-serialize
    let userData;
    try {
      userData = JSON.parse(Buffer.from(cookie, 'base64').toString('utf8'));
    } catch (e) {
      return res.send('<h1>Erro</h1><p>Cookie inválido ou corrompido.</p><a href="/cookie">Voltar</a>');
    }

    res.send(`
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Cookie Atual</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
        </style>
      </head>
      <body>
        <h1>Dados do Cookie</h1>
        <pre>${escapeHtml(JSON.stringify(userData, null, 2))}</pre>
        <p><a href="/cookie">← Voltar</a></p>
      </body>
      </html>
    `);
  } else {
    res.send(`
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Sem Cookie</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
        </style>
      </head>
      <body>
        <h1>Nenhum Cookie Encontrado</h1>
        <p><a href="/cookie">← Criar Cookie</a></p>
      </body>
      </html>
    `);
  }
});

// VULNERABILIDADE 7: XML External Entity (XXE) (CWE-611)
app.get('/xml', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Processar XML</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        textarea { width: 100%; max-width: 500px; height: 200px; padding: 10px; font-family: monospace; }
        button { padding: 10px 20px; font-size: 16px; }
      </style>
    </head>
    <body>
      <h1>Processar Documento XML</h1>
      <form action="/xml" method="POST">
        <textarea name="xml" placeholder="Cole seu XML aqui..." required><?xml version="1.0"?>
<dados>
  <nome>João Silva</nome>
  <email>joao@exemplo.com</email>
</dados></textarea><br>
        <button type="submit">Processar</button>
      </form>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.post('/xml', (req, res) => {
  const xmlData = req.body.xml;

  // Validação da entrada
  if (!xmlData || typeof xmlData !== 'string') {
    return res.status(400).send('<h1>Erro</h1><p>Dados XML inválidos.</p><a href="/xml">Voltar</a>');
  }

  // Limitar tamanho do XML para prevenir ataques de negação de serviço
  if (xmlData.length > 10000) {
    return res.status(400).send('<h1>Erro</h1><p>XML muito grande (máximo 10KB).</p><a href="/xml">Voltar</a>');
  }

  // Rejeitar DTDs e entidades externas no conteúdo bruto
  if (/<!DOCTYPE/i.test(xmlData) || /<!ENTITY/i.test(xmlData) || /SYSTEM/i.test(xmlData) || /PUBLIC/i.test(xmlData)) {
    return res.status(400).send('<h1>Erro</h1><p>DTDs e entidades externas não são permitidos.</p><a href="/xml">Voltar</a>');
  }

  try {
    // CORREÇÃO CWE-611: Desabilitar entidades externas e acesso à rede no parsing XML
    const xmlDoc = libxmljs.parseXml(xmlData, {
      noblanks: true,
      noent: false,   // NÃO expandir entidades externas
      nonet: true,    // Bloquear acesso à rede
      nocdata: true,
      dtdload: false, // Não carregar DTDs externos
      dtdvalid: false // Não validar contra DTDs
    });
    
    res.send(`
      <html>
      <head>
        <meta charset="UTF-8">
        <title>XML Processado</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          pre { background: #f4f4f4; padding: 15px; border: 1px solid #ddd; }
        </style>
      </head>
      <body>
        <h1>XML Processado com Sucesso</h1>
        <pre>${escapeHtml(xmlDoc.toString())}</pre>
        <p><a href="/xml">← Voltar</a></p>
      </body>
      </html>
    `);
  } catch (err) {
    res.send(`<h1>Erro ao processar XML</h1><p>${escapeHtml(err.message)}</p><a href="/xml">Voltar</a>`);
  }
});

// VULNERABILIDADE 8: Server-Side Request Forgery (SSRF) (CWE-918)
app.get('/proxy', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Proxy Request</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        input, button { padding: 10px; margin: 5px; font-size: 16px; }
      </style>
    </head>
    <body>
      <h1>Fazer Requisição via Proxy</h1>
      <form action="/proxy" method="POST">
        <input type="text" name="url" placeholder="URL para acessar" style="width: 400px;" required>
        <button type="submit">Buscar</button>
      </form>
      <p>Exemplo: http://exemplo.com</p>
      <p><a href="/">← Voltar</a></p>
    </body>
    </html>
  `);
});

app.post('/proxy', (req, res) => {
  const userUrl = req.body.url;

  // Validação da entrada
  if (!userUrl || typeof userUrl !== 'string') {
    return res.status(400).send('<h1>Erro</h1><p>URL inválida.</p><a href="/proxy">Voltar</a>');
  }

  // CORREÇÃO CWE-918: Validação rigorosa da URL para prevenir SSRF
  let parsedUrl;
  try {
    parsedUrl = new URL(userUrl);
  } catch (e) {
    return res.status(400).send('<h1>Erro</h1><p>URL mal formatada.</p><a href="/proxy">Voltar</a>');
  }

  // Permitir apenas protocolos seguros
  const allowedProtocols = ['http:', 'https:'];
  if (!allowedProtocols.includes(parsedUrl.protocol)) {
    return res.status(400).send('<h1>Erro</h1><p>Protocolo não permitido. Use http ou https.</p><a href="/proxy">Voltar</a>');
  }

  // Bloquear hostnames internos/privados
  const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '[::1]', 'metadata.google.internal', '169.254.169.254'];
  const hostname = parsedUrl.hostname.toLowerCase();
  if (blockedHosts.includes(hostname)) {
    return res.status(403).send('<h1>Erro</h1><p>Acesso a endereços internos não é permitido.</p><a href="/proxy">Voltar</a>');
  }

  // Bloquear ranges de IP privados/reservados
  if (net.isIP(hostname)) {
    const parts = hostname.split('.').map(Number);
    const isPrivate = (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 0 ||
      parts[0] === 127 ||
      (parts[0] === 169 && parts[1] === 254)
    );
    if (isPrivate) {
      return res.status(403).send('<h1>Erro</h1><p>Acesso a IPs privados/reservados não é permitido.</p><a href="/proxy">Voltar</a>');
    }
  }

  // Whitelist de domínios permitidos (opcional - descomente para restringir)
  // const allowedDomains = ['exemplo.com', 'api.exemplo.com'];
  // if (!allowedDomains.some(d => hostname === d || hostname.endsWith('.' + d))) {
  //   return res.status(403).send('<h1>Erro</h1><p>Domínio não permitido.</p><a href="/proxy">Voltar</a>');
  // }

  // Usar módulos nativos http/https em vez do depreciado 'request'
  const client = parsedUrl.protocol === 'https:' ? https : http;
  const proxyReq = client.get(parsedUrl.toString(), { timeout: 5000 }, (proxyRes) => {
    let body = '';
    proxyRes.on('data', (chunk) => { body += chunk; });
    proxyRes.on('end', () => {
      // Limitar tamanho da resposta exibida
      const truncatedBody = body.length > 10000 ? body.substring(0, 10000) + '\n... (truncado)' : body;
      res.send(`
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Resposta do Proxy</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            pre { background: #f4f4f4; padding: 15px; border: 1px solid #ddd; max-height: 500px; overflow: auto; }
          </style>
        </head>
        <body>
          <h1>Resposta da URL: ${escapeHtml(userUrl)}</h1>
          <p><strong>Status:</strong> ${proxyRes.statusCode}</p>
          <pre>${escapeHtml(truncatedBody)}</pre>
          <p><a href="/proxy">← Voltar</a></p>
        </body>
        </html>
      `);
    });
  });

  proxyReq.on('error', (error) => {
    res.send(`<h1>Erro</h1><p>${escapeHtml(error.message)}</p><a href="/proxy">Voltar</a>`);
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    res.send('<h1>Erro</h1><p>Timeout ao acessar a URL.</p><a href="/proxy">Voltar</a>');
  });
});

// Página de documentação das vulnerabilidades
app.get('/vulnerabilidades', (req, res) => {
  const vulnerabilidades = fs.readFileSync(path.join(__dirname, 'VULNERABILIDADES.md'), 'utf8');
  res.send(`
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Documentação das Vulnerabilidades</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; max-width: 900px; }
        pre { background: #f4f4f4; padding: 15px; border-left: 4px solid #d32f2f; overflow-x: auto; }
        h2 { color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 5px; }
        h3 { color: #1976d2; }
      </style>
    </head>
    <body>
      <h1>📚 Documentação das Vulnerabilidades</h1>
      <div>${vulnerabilidades.replace(/```/g, '<pre>').replace(/\n/g, '<br>')}</div>
      <p><a href="/">← Voltar à página inicial</a></p>
    </body>
    </html>
  `);
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════════════════════════════════╗
  ║  ⚠️  APLICAÇÃO VULNERÁVEL NODE.JS - PARA TESTES VERACODE  ⚠️   ║
  ╚════════════════════════════════════════════════════════════════╝
  
  🚀 Servidor rodando em: http://localhost:${PORT}
  
  ⚠️  AVISO: Esta aplicação contém vulnerabilidades INTENCIONAIS
      para fins de teste com ferramentas SAST e SCA.
      NÃO USE EM PRODUÇÃO!
  
  📚 Vulnerabilidades implementadas:
     1. SQL Injection (CWE-89)
     2. Cross-Site Scripting - XSS (CWE-79)
     3. Command Injection (CWE-78)
     4. Path Traversal (CWE-22)
     5. Hardcoded Credentials (CWE-798)
     6. Insecure Deserialization (CWE-502)
     7. XML External Entity - XXE (CWE-611)
     8. Server-Side Request Forgery - SSRF (CWE-918)
  
  🔍 Acesse http://localhost:${PORT} para ver todas as funcionalidades
  `);
});
