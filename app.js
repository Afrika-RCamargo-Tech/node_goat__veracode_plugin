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
const { exec } = require('child_process');
const serialize = require('node-serialize');
const libxmljs = require('libxmljs');
const request = require('request');

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILIDADE: Credenciais codificadas (CWE-798)
const DB_USER = 'admin';
const DB_PASSWORD = 'senha123';
const API_KEY = 'sk-1234567890abcdefghijklmnopqrstuvwxyz';

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
  
  // VULNERABILIDADE: SQL Injection - concatenação direta sem sanitização
  const query = `SELECT * FROM usuarios WHERE email = '${email}'`;
  
  db.all(query, (err, rows) => {
    if (err) {
      res.send(`<h1>Erro</h1><p>${err.message}</p><a href="/">Voltar</a>`);
    } else {
      let html = '<h1>Resultados da Busca</h1>';
      if (rows.length > 0) {
        html += '<ul>';
        rows.forEach(row => {
          html += `<li>Nome: ${row.nome}, Email: ${row.email}, Perfil: ${row.perfil}</li>`;
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
  
  // VULNERABILIDADE: XSS - Reflected XSS sem sanitização
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
        ${comentario}
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
  
  // VULNERABILIDADE: Command Injection - execução direta de comando sem validação
  exec(comando, (error, stdout, stderr) => {
    let output = '';
    if (error) {
      output = `Erro: ${error.message}`;
    } else if (stderr) {
      output = `Stderr: ${stderr}`;
    } else {
      output = stdout;
    }
    
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
        <pre>${output}</pre>
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
  
  // VULNERABILIDADE: Path Traversal - sem validação do caminho
  const filepath = path.join(__dirname, filename);
  
  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) {
      res.send(`<h1>Erro</h1><p>Arquivo não encontrado: ${err.message}</p><a href="/arquivo">Voltar</a>`);
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
          <h1>Conteúdo: ${filename}</h1>
          <pre>${data}</pre>
          <p><a href="/arquivo">← Voltar</a></p>
        </body>
        </html>
      `);
    }
  });
});

// VULNERABILIDADE 5: Hardcoded Credentials (CWE-798)
app.get('/config', (req, res) => {
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
        <p><strong>Usuário do Banco:</strong> ${DB_USER}</p>
        <p><strong>Senha do Banco:</strong> ${DB_PASSWORD}</p>
        <p><strong>API Key:</strong> ${API_KEY}</p>
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
  
  // VULNERABILIDADE: Insecure Deserialization - serialização sem validação
  const serialized = serialize.serialize(JSON.parse(userData));
  res.cookie('userData', serialized);
  
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
    // VULNERABILIDADE: Deserialização insegura
    const userData = serialize.unserialize(cookie);
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
        <pre>${JSON.stringify(userData, null, 2)}</pre>
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
  
  try {
    // VULNERABILIDADE: XXE - parsing de XML sem desabilitar entidades externas
    const xmlDoc = libxmljs.parseXml(xmlData, { noblanks: true, noent: true, nocdata: true });
    
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
        <pre>${xmlDoc.toString()}</pre>
        <p><a href="/xml">← Voltar</a></p>
      </body>
      </html>
    `);
  } catch (err) {
    res.send(`<h1>Erro ao processar XML</h1><p>${err.message}</p><a href="/xml">Voltar</a>`);
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
  const url = req.body.url;
  
  // VULNERABILIDADE: SSRF - requisição sem validação de URL
  request(url, (error, response, body) => {
    if (error) {
      res.send(`<h1>Erro</h1><p>${error.message}</p><a href="/proxy">Voltar</a>`);
    } else {
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
          <h1>Resposta da URL: ${url}</h1>
          <p><strong>Status:</strong> ${response.statusCode}</p>
          <pre>${body}</pre>
          <p><a href="/proxy">← Voltar</a></p>
        </body>
        </html>
      `);
    }
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
