'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {createShareHandler}=require('./share.cjs');
const {createSpaceChecklistHandler}=require('./space-checklist.cjs');
const root=path.join(__dirname,'public');
const password=process.env.CATALOG_PASSWORD;if(!password)throw Error('Configure CATALOG_PASSWORD no ambiente do servidor.');
const digest=value=>crypto.createHash('sha256').update(value).digest();
const expected=digest(password),ttl=24*60*60*1000;
const sessionKey=crypto.scryptSync(password,'emc-catalog-session-v1',32);
function sessionMac(purpose,value){
 return crypto.createHmac('sha256',sessionKey).update(purpose).update(':').update(value).digest();
}
function validSession(req){
 const token=(req.headers.cookie||'').split(';').map(value=>value.trim()).find(value=>value.startsWith('emc_session='))?.slice(12);
 const match=token?.match(/^(\d{13}\.[0-9a-f]{64})\.([0-9a-f]{64})$/);
 if(!match||Number(match[1].split('.')[0])<=Date.now())return null;
 return crypto.timingSafeEqual(sessionMac('cookie',match[1]),Buffer.from(match[2],'hex'))?match[1]:null;
}
function authorized(req){return validSession(req)!==null}
function sessionResponse(res,session,headers={}){
 res.writeHead(session?200:401,{'Content-Type':'application/json','Cache-Control':'no-store',...headers});
 res.end(JSON.stringify(session?{ok:true,wrapKey:sessionMac('browser',session).toString('base64')}:{ok:false}));
}
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.bin':'application/octet-stream'};
const sharedRequest=createShareHandler({root,password,authorized});
const spaceChecklistRequest=createSpaceChecklistHandler();
const publicPages = new Map([
 ['/', 'entrada.html'],
 ['/emc', 'index.html'],
 ['/index.html', 'index.html'],
 ['/space-jump', 'space-jump.html']
]);
const publicAssets = new Set([
 '/entradas.css',
 '/assets/f1ac55cd8529aafd7b72d878.png',
 '/assets/space-power-jump-logo.png'
]);
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');
 let url,pathname;try{url=new URL(req.url,'http://localhost');pathname=decodeURIComponent(url.pathname)}catch{res.writeHead(400).end();return}
 if(pathname==='/health'){res.writeHead(200,{'Content-Type':'application/json'}).end('{"ok":true}');return}
 if(pathname==='/api/session'&&req.method==='GET'){sessionResponse(res,validSession(req));return}
 if(pathname==='/api/login'&&req.method==='POST'){
  if(req.headers.origin){try{if(new URL(req.headers.origin).host!==req.headers.host){res.writeHead(403).end();return}}catch{res.writeHead(403).end();return}}
  let body='';try{for await(const chunk of req){body+=chunk;if(body.length>4096){res.writeHead(413).end();return}}const provided=JSON.parse(body).password;if(typeof provided!=='string'||!crypto.timingSafeEqual(digest(provided),expected)){res.writeHead(401).end();return}}catch{res.writeHead(400).end();return}
  const session=(Date.now()+ttl)+'.'+crypto.randomBytes(32).toString('hex');
  const token=session+'.'+sessionMac('cookie',session).toString('hex');
  const secure=req.socket.encrypted||req.headers['x-forwarded-proto']==='https';
  sessionResponse(res,session,{'Set-Cookie':`emc_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${ttl/1000}${secure?'; Secure':''}`});
  return
 }
 if(await sharedRequest(req,res,pathname))return;
 if(await spaceChecklistRequest(req,res,pathname))return;
 if(!['GET','HEAD'].includes(req.method)){res.writeHead(405).end();return}
 if(pathname==='/emc/'||pathname==='/space-jump/'){
  res.writeHead(308,{Location:pathname.slice(0,-1)+url.search}).end();return
 }
 const entry=publicPages.get(pathname);
 if(!entry&&!publicAssets.has(pathname)&&!authorized(req)){res.writeHead(401,{'Cache-Control':'no-store'}).end();return}
 const file=path.resolve(root,entry||'.'+pathname);if(!file.startsWith(root+path.sep)){res.writeHead(403).end();return}
 let stat;try{stat=await fs.promises.stat(file);if(!stat.isFile())throw Error()}catch{res.writeHead(404).end();return}
 res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Content-Length':stat.size,'Cache-Control':entry?'no-store':'private, max-age=86400'});if(req.method==='HEAD'){res.end();return}const stream=fs.createReadStream(file);stream.on('error',()=>res.destroy());stream.pipe(res)
});
server.listen(Number(process.env.PORT||8080),process.env.HOST||'127.0.0.1',()=>console.log('Catálogo EMC iniciado.'));

