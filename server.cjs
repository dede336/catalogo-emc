'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {createShareHandler}=require('./share.cjs');
const root=path.join(__dirname,'public'),sessions=new Map();
const password=process.env.CATALOG_PASSWORD;if(!password)throw Error('Configure CATALOG_PASSWORD no ambiente do servidor.');
const digest=value=>crypto.createHash('sha256').update(value).digest();
const expected=digest(password),ttl=12*60*60*1000;
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.bin':'application/octet-stream'};
function authorized(req){const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('emc_session='))?.slice(12);const expires=sessions.get(token);if(expires>Date.now())return true;if(token)sessions.delete(token);return false}
const sharedRequest=createShareHandler({root,password,authorized});
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');
 let pathname;try{pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname)}catch{res.writeHead(400).end();return}
 if(pathname==='/health'){res.writeHead(200,{'Content-Type':'application/json'}).end('{"ok":true}');return}
 if(pathname==='/api/login'&&req.method==='POST'){
  if(req.headers.origin){try{if(new URL(req.headers.origin).host!==req.headers.host){res.writeHead(403).end();return}}catch{res.writeHead(403).end();return}}
  let body='';try{for await(const chunk of req){body+=chunk;if(body.length>4096){res.writeHead(413).end();return}}const provided=JSON.parse(body).password;if(typeof provided!=='string'||!crypto.timingSafeEqual(digest(provided),expected)){res.writeHead(401).end();return}}catch{res.writeHead(400).end();return}
  for(const [token,expires] of sessions)if(expires<=Date.now())sessions.delete(token);
  const token=crypto.randomBytes(32).toString('hex');sessions.set(token,Date.now()+ttl);const secure=req.socket.encrypted||req.headers['x-forwarded-proto']==='https';
  res.writeHead(200,{'Set-Cookie':`emc_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${ttl/1000}${secure?'; Secure':''}`,'Content-Type':'application/json','Cache-Control':'no-store'}).end('{"ok":true}');return
 }
 if(await sharedRequest(req,res,pathname))return;
 if(!['GET','HEAD'].includes(req.method)){res.writeHead(405).end();return}
 const entry=pathname==='/'||pathname==='/index.html';
 const publicLogo=pathname==='/assets/f1ac55cd8529aafd7b72d878.png';
 if(!entry&&!publicLogo&&!authorized(req)){res.writeHead(401,{'Cache-Control':'no-store'}).end();return}
 const file=path.resolve(root,entry?'index.html':'.'+pathname);if(!file.startsWith(root+path.sep)){res.writeHead(403).end();return}
 let stat;try{stat=await fs.promises.stat(file);if(!stat.isFile())throw Error()}catch{res.writeHead(404).end();return}
 res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Content-Length':stat.size,'Cache-Control':entry?'no-store':'private, max-age=86400'});if(req.method==='HEAD'){res.end();return}const stream=fs.createReadStream(file);stream.on('error',()=>res.destroy());stream.pipe(res)
});
server.listen(Number(process.env.PORT||8080),process.env.HOST||'127.0.0.1',()=>console.log('Catálogo EMC iniciado.'));

