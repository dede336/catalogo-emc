'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { gunzip } = require('node:zlib');

const deriveKey = promisify(crypto.pbkdf2);
const unzip = promisify(gunzip);
const lifetime = 7 * 24 * 60 * 60;
const modelPattern = /^(?:[1-9]|1[0-9]|2[0-5]|cama2m|tramp[1-7])$/;
const tokenPattern = /^([a-z0-9]+)\.(\d{10})\.([a-f0-9]{32})\.([a-f0-9]{64})$/;
const privateHeaders = {'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer'};

function message(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {...privateHeaders,'Content-Type':type}).end(body);
  return true;
}

async function readShareKey(file) {
  try {
    await fs.writeFile(file, crypto.randomBytes(32), {flag:'wx',mode:0o600});
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const key = await fs.readFile(file);
  if (key.length !== 32) throw Error('Chave de compartilhamento inválida.');
  return key;
}

function signature(key, payload) {
  return crypto.createHmac('sha256',key).update(payload).digest('hex');
}

function modelSource(html, model) {
  const tag = id => html.match(new RegExp('<script id="'+id+'"[^>]*>'))?.[0];
  const attr = (element, name) => element?.match(new RegExp(' data-'+name+'="([^"]+)"'))?.[1];
  const source = tag(model === '1' ? 'modelFirst' : 'm'+model+'data');
  const salt = attr(model === '1' ? tag('model') : source,'salt');
  const iv = attr(source,'iv');
  const file = attr(source,'path')?.split('?')[0];
  if (!salt || !iv || !/^assets\/[A-Za-z0-9_-]+\.bin$/.test(file || '')) return null;
  return {salt,iv,file};
}

async function readModel(source, root, password) {
  const data = await fs.readFile(path.join(root,source.file));
  const key = await deriveKey(password,Buffer.from(source.salt,'base64'),250000,32,'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(source.iv,'base64'));
  decipher.setAuthTag(data.subarray(-16));
  const plain = Buffer.concat([decipher.update(data.subarray(0,-16)),decipher.final()]);
  return plain[0] === 31 && plain[1] === 139 ? unzip(plain,{maxOutputLength:100*1024*1024}) : plain;
}

function sharedPage(html, model, expires) {
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match=>match[1]);
  const library = scripts.find(s=>s.includes('window.__emc3d={'));
  const libraryEnd = library.indexOf(';',library.indexOf('window.__emc3d={'));
  const libraryCode = library.slice(0,libraryEnd+1)+'})();';
  const dimensions = scripts.find(s=>s.includes('window.emcAddDimensions=(num,object'));
  const start = scripts.find(s=>s.includes('function standaloneStart('));
  const viewer = start.slice(start.indexOf('async function standaloneStart('),start.indexOf('\nfunction libraryCode()'));
  const trampoline = model.startsWith('tramp');
  const adjustments = trampoline ? scripts.find(s=>s.includes('window.emcTrampolineMetal = function')) : '';
  const gray = trampoline ? adjustments.match(/window\.emcLightenTrampolineGray = [\s\S]*?\n\};/)[0] : '';
  const metal = trampoline ? adjustments.match(/window\.emcTrampolineMetal = [\s\S]*?\n\};/)[0] : '';
  const number = /^\d+$/.test(model) ? Number(model) : model;
  const title = trampoline ? 'Trampolim Modelo '+model.slice(5) : model === 'cama2m' ? 'Cama elástica 2 m' : 'Playground Modelo '+model;
  const call = `const expiresAt=${expires*1000};
function expire(){
 if(Date.now()<expiresAt)return;
 document.getElementById('stage')?.remove();
 document.getElementById('toolbar')?.remove();
 const notice=document.getElementById('notice');
 notice.textContent='Link expirado. Peça um novo compartilhamento ao vendedor.';
}
setTimeout(expire,Math.max(0,expiresAt-Date.now()));
document.addEventListener('visibilitychange',expire);
if(Date.now()<expiresAt) standaloneStart(${JSON.stringify(number)},window.emcLightenTrampolineGray,window.emcTrampolineMetal,location.pathname.replace(/\\/$/,'')+'/modelo.glb');
else expire();`;
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>${title}</title><style>
*{box-sizing:border-box}body{margin:0;background:#e8edf2;font:16px system-ui,sans-serif;color:#243746}
header{position:absolute;inset:0 0 auto;z-index:2;padding:14px 18px;background:#152131;color:white;font-weight:700}
#stage{position:absolute;inset:0;overflow:hidden}canvas{display:block;touch-action:none}
#toolbar{position:absolute;z-index:2;bottom:calc(16px + env(safe-area-inset-bottom,0px));left:50%;transform:translateX(-50%)}
#toolbar button{background:#263c49;color:white;border:0;border-radius:8px;padding:12px 16px;font:600 14px system-ui;white-space:nowrap}
#notice{position:absolute;z-index:1;inset:auto 12px 70px;text-align:center;pointer-events:none;font-size:14px}</style></head>
<body><header>${title}</header><main id="stage"></main><p id="notice" role="status">Carregando 3D…</p><div id="toolbar"></div>
<script>${libraryCode}</script><script>${dimensions}</script><script>${gray}\n${metal}\n${viewer}\n${call}</script></body></html>`;
}

function createShareHandler({root,password,authorized}) {
  let secret;
  const getSecret = () => secret ??= readShareKey(path.join(path.dirname(root),'.env.share-key'));
  return async function sharedRequest(req,res,pathname) {
    const issuing = pathname === '/api/share';
    if (!issuing && !pathname.startsWith('/compartilhado/')) return false;
    try {
      if (issuing) {
        if (req.method !== 'POST') return message(res,405,'Método não permitido.');
        if (!authorized(req)) return message(res,401,'Entre no catálogo para compartilhar.');
        if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) {
          return message(res,403,'Origem inválida.');
        }
        let body = '';
        for await (const part of req) {
          body += part;
          if (body.length>256) return message(res,413,'Solicitação grande demais.');
        }
        let model;
        try { model = JSON.parse(body)?.model; } catch {}
        const html = await fs.readFile(path.join(root,'index.html'),'utf8');
        if (typeof model !== 'string' || !modelPattern.test(model) || !modelSource(html,model)) {
          return message(res,404,'Modelo indisponível.');
        }
        const expires = Math.floor(Date.now()/1000)+lifetime;
        const payload = model+'.'+expires+'.'+crypto.randomBytes(16).toString('hex');
        const token = payload+'.'+signature(await getSecret(),payload);
        return message(res,201,JSON.stringify({path:'/compartilhado/'+token,expires}),'application/json');
      }
      if (req.method !== 'GET') return message(res,405,'Método não permitido.');
      const [, , token, file, extra] = pathname.split('/');
      const match = tokenPattern.exec(token);
      if (!match || extra !== undefined || (file && file !== 'modelo.glb') || !modelPattern.test(match[1])) {
        return message(res,404,'Link inválido.');
      }
      const [,model,expires,nonce,mac] = match;
      const expected = signature(await getSecret(),model+'.'+expires+'.'+nonce);
      if (!crypto.timingSafeEqual(Buffer.from(mac,'hex'),Buffer.from(expected,'hex'))) {
        return message(res,404,'Link inválido.');
      }
      if (Date.now() >= Number(expires)*1000) {
        return message(res,410,'Link expirado. Peça um novo compartilhamento ao vendedor.');
      }
      const html = await fs.readFile(path.join(root,'index.html'),'utf8');
      const source = modelSource(html,model);
      if (!source) return message(res,404,'Modelo indisponível.');
      if (file) {
        const modelData = await readModel(source,root,password);
        if (Date.now() >= Number(expires)*1000) {
          return message(res,410,'Link expirado. Peça um novo compartilhamento ao vendedor.');
        }
        return message(res,200,modelData,'model/gltf-binary');
      }
      return message(res,200,sharedPage(html,model,Number(expires)),'text/html; charset=utf-8');
    } catch (error) {
      console.error('Falha ao compartilhar modelo:',error.message);
      return message(res,500,'Não foi possível abrir o compartilhamento.');
    }
  };
}

module.exports = {createShareHandler};
