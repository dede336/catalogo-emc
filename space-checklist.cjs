'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const route = '/space-jump/checklist';
const cookieName = 'space_session';
const sessionSeconds = 24 * 60 * 60;
const noStore = {'Cache-Control': 'no-store'};
const digest = value => crypto.createHash('sha256').update(value).digest();

function readPassword() {
  if (process.env.SPACE_CHECKLIST_PASSWORD) return process.env.SPACE_CHECKLIST_PASSWORD;
  const file = path.join(os.homedir(), '.config', 'catalogo-emc', 'space-checklist-password');
  try {
    return fs.readFileSync(file, 'utf8').replace(/\r?\n$/, '');
  } catch (error) {
    if (error.code !== 'ENOENT') console.error('Não foi possível ler a senha do checklist:', error.code);
    return '';
  }
}

function createSpaceChecklistHandler() {
  let checklist, passwordHash, sessionKey;
  const password = readPassword();
  if (password) {
    try {
      const sealed = fs.readFileSync(path.join(__dirname, 'private', 'space-checklist.html.gz.enc'));
      const salt = sealed.subarray(0, 16);
      const iv = sealed.subarray(16, 28);
      const tag = sealed.subarray(28, 44);
      const key = crypto.scryptSync(password, salt, 32);
      const decoder = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decoder.setAuthTag(tag);
      checklist = Buffer.concat([decoder.update(sealed.subarray(44)), decoder.final()]);
      passwordHash = digest(password);
      sessionKey = crypto.createHmac('sha256', key).update('space-checklist-session-v1').digest();
      key.fill(0);
    } catch {
      console.error('O checklist da Space não abriu. Confira a senha configurada e o arquivo protegido.');
    }
  }

  const sign = token => crypto.createHmac('sha256', sessionKey).update(token).digest();
  function signedIn(req) {
    const token = (req.headers.cookie || '').split(';').map(item => item.trim())
      .find(item => item.startsWith(cookieName + '='))?.slice(cookieName.length + 1);
    const parsed = token?.match(/^(\d{13}\.[a-f\d]{48})\.([a-f\d]{64})$/);
    return Boolean(parsed && Number(parsed[1].split('.')[0]) > Date.now() &&
      crypto.timingSafeEqual(sign(parsed[1]), Buffer.from(parsed[2], 'hex')));
  }

  function form(res, status, method) {
    const error = status === 401 ? '<p class="space-auth-error" role="alert">Senha incorreta.</p>' : '';
    res.writeHead(status, {...noStore, 'Content-Type': 'text/html; charset=utf-8'});
    if (method === 'HEAD') return res.end();
    res.end(`<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Checklist de estoque · Space Power Jump</title>
  <link rel="stylesheet" href="/entradas.css">
</head>
<body class="space-page">
  <header class="space-header"><a href="/space-jump">← Voltar ao Space Power Jump</a></header>
  <main class="space-main">
    <form class="space-auth" action="${route}" method="post">
      <h1>Checklist de estoque</h1>
      ${error}
      <label for="space-password">Senha da equipe</label>
      <input type="password" id="space-password" name="password" autocomplete="current-password" required>
      <button class="space-tool" type="submit">Entrar</button>
    </form>
  </main>
</body>
</html>`);
  }

  return async (req, res, pathname) => {
    if (pathname !== route) return false;
    if (!checklist) {
      res.writeHead(503, {...noStore, 'Content-Type': 'text/plain; charset=utf-8'});
      res.end('O acesso ao checklist ainda não está disponível.');
      return true;
    }

    if (req.method === 'POST') {
      if (req.headers.origin) {
        try {
          if (new URL(req.headers.origin).host !== req.headers.host) throw Error();
        } catch {
          res.writeHead(403, noStore).end();
          return true;
        }
      }
      let body = '';
      try {
        for await (const chunk of req) {
          body += chunk;
          if (body.length > 4096) {
            res.writeHead(413, noStore).end();
            return true;
          }
        }
      } catch {
        if (!res.destroyed) res.writeHead(400, noStore).end();
        return true;
      }
      const provided = new URLSearchParams(body).get('password');
      if (!provided || !crypto.timingSafeEqual(digest(provided), passwordHash)) {
        form(res, 401, req.method);
        return true;
      }
      const token = (Date.now() + sessionSeconds * 1000) + '.' + crypto.randomBytes(24).toString('hex');
      const signature = sign(token).toString('hex');
      const secure = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
      res.writeHead(303, {
        ...noStore,
        Location: route,
        'Set-Cookie': `${cookieName}=${token}.${signature}; Path=/space-jump; HttpOnly; SameSite=Lax; Max-Age=${sessionSeconds}${secure ? '; Secure' : ''}`
      }).end();
    } else if (req.method === 'GET' || req.method === 'HEAD') {
      if (!signedIn(req)) {
        form(res, 200, req.method);
      } else {
        res.writeHead(200, {
          ...noStore,
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'gzip',
          'Content-Length': checklist.length
        }).end(req.method === 'HEAD' ? undefined : checklist);
      }
    } else {
      res.writeHead(405, {...noStore, Allow: 'GET, HEAD, POST'}).end();
    }
    return true;
  };
}

module.exports = {createSpaceChecklistHandler};
