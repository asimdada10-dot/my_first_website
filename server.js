'use strict';
// Dada Footwear Maintenance - zero-dependency backend (Node >= 22.13: node:sqlite)
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=+process.env.PORT||3000,DATA=process.env.DATA_DIR||path.join(__dirname,'data'),PUB=path.join(__dirname,'public');
const SECURE=process.env.COOKIE_SECURE==='true',DBF=path.join(DATA,'app.db'),cmd=process.argv[2];
fs.mkdirSync(path.join(DATA,'uploads'),{recursive:true});
if(cmd==='restore'){ // node server.js restore backup.db  (server must be stopped)
  const src=process.argv[3];if(!src||!fs.existsSync(src)){console.error('Usage: node server.js restore <backup.db>');process.exit(1)}
  const t=new DatabaseSync(src,{readOnly:true});
  if(t.prepare('PRAGMA integrity_check').get().integrity_check!=='ok'||!t.prepare("SELECT name FROM sqlite_master WHERE name='users'").get()){console.error('Not a valid backup');process.exit(1)}
  t.close();for(const x of['','-wal','-shm'])fs.rmSync(DBF+x,{force:true});fs.copyFileSync(src,DBF);console.log('Restored. Start the server again.');process.exit(0)}
const db=new DatabaseSync(DBF);
db.exec(`PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL COLLATE NOCASE,full_name TEXT NOT NULL,emp_id TEXT,contact TEXT,department TEXT,hall TEXT,role TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',perms TEXT,photo TEXT,pw TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(res TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,created_by TEXT,updated_by TEXT,updated_at TEXT,PRIMARY KEY(res,id));
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts TEXT DEFAULT CURRENT_TIMESTAMP,user TEXT,action TEXT,detail TEXT);`);
if(cmd==='backup'){const f=path.resolve(process.argv[3]||`backup-${new Date().toISOString().slice(0,10)}.db`);fs.rmSync(f,{force:true});db.exec(`VACUUM INTO '${f.replace(/'/g,"''")}'`);console.log('Backup written to',f);process.exit(0)}

const RES=['machines','orders','preventive','spares','team'],ACT=['view','add','edit','delete','export'];
const VALID={...Object.fromEntries(RES.map(r=>[r,ACT])),users:['view','add','edit','delete'],settings:['view','edit'],audit:['view'],backup:['export','import']};
const ALLP=Object.entries(VALID).flatMap(([r,a])=>a.map(x=>r+'.'+x)),all=(rs,as=ACT)=>rs.flatMap(r=>as.map(a=>r+'.'+a));
const ROLE={super_admin:['*'],
 admin:[...all(RES),...all(['users'],['view','add','edit']),'settings.view','settings.edit','audit.view','backup.export','backup.import'],
 manager:[...all(RES,['view','add','edit','export']),'settings.view','audit.view'],
 technician:[...all(RES,['view']),'orders.add','orders.edit','preventive.edit','spares.edit'],
 operator:[...all(RES,['view']),'orders.add'],viewer:all(RES,['view'])};
const DEF={company:'Dada Footwear',logo:'',lists:{departments:['Maintenance','Production','Stores'],halls:['Stitching','Production Hall A'],lines:[],categories:[],maintenanceTypes:['Breakdown','Preventive','Inspection'],priorities:['Low','Medium','High','Critical'],statuses:['Open','Assigned','In Progress','Waiting for Parts','Completed','Cancelled'],jobTitles:['Technician','Senior Technician','Maintenance Manager']},labels:{en:{},ur:{}}};

class HttpErr extends Error{constructor(c,m,x){super(m);this.c=c;this.x=x}}
const bad=m=>new HttpErr(400,m),sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const log=(u,a,d)=>db.prepare('INSERT INTO audit(user,action,detail) VALUES(?,?,?)').run(u,a,String(d).slice(0,500));
const hashPw=p=>{const s=crypto.randomBytes(16);return 's1$'+s.toString('hex')+'$'+crypto.scryptSync(p,s,64).toString('hex')};
const checkPw=(p,st)=>{const [,s,h]=st.split('$'),a=crypto.scryptSync(p,Buffer.from(s,'hex'),64),b=Buffer.from(h,'hex');return crypto.timingSafeEqual(a,b)};
const DUMMY=hashPw('x-dummy-password');
const permsOf=u=>u.role==='super_admin'?['*']:(u.perms?JSON.parse(u.perms):ROLE[u.role]||[]);
const can=(u,p)=>{const x=permsOf(u);return x.includes('*')||x.includes(p)};
const need=(u,p)=>{if(!can(u,p))throw new HttpErr(403,'Permission denied ('+p+')')};
const pub=u=>({id:u.id,username:u.username,full_name:u.full_name,emp_id:u.emp_id,contact:u.contact,department:u.department,hall:u.hall,role:u.role,status:u.status,photo:u.photo,custom:!!u.perms,perms:permsOf(u),created_at:u.created_at});
const getCfg=()=>{const r=db.prepare("SELECT v FROM settings WHERE k='config'").get();return r?JSON.parse(r.v):structuredClone(DEF)};
const setCfg=c=>db.prepare("INSERT INTO settings(k,v) VALUES('config',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify(c));

// ---- bootstrap: first Super Admin comes from env or a random one-time password (never hardcoded)
if(!db.prepare('SELECT 1 FROM users').get()){
  const un=process.env.ADMIN_USERNAME||'admin',pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(9).toString('base64url');
  if(pw.length<10){console.error('ADMIN_PASSWORD must be at least 10 characters');process.exit(1)}
  db.prepare("INSERT INTO users(username,full_name,role,pw) VALUES(?,?,?,?)").run(un,'Super Administrator','super_admin',hashPw(pw));
  log('system','bootstrap','Super Admin created');
  console.log(`\n=== FIRST RUN: Super Admin created ===\n username: ${un}\n password: ${process.env.ADMIN_PASSWORD?'(from ADMIN_PASSWORD)':pw}\n Change it after logging in (Users page). This is shown only once.\n`);
}
if(!db.prepare("SELECT 1 FROM settings WHERE k='config'").get())setCfg(DEF);
if(process.env.SEED_EXAMPLE!=='false'&&!db.prepare('SELECT 1 FROM records').get()){ // initial example data from the brief
  const put=(r,o)=>db.prepare("INSERT INTO records(res,id,data,created_by,updated_by,updated_at) VALUES(?,?,?,'system','system',?)").run(r,o.id,JSON.stringify(o),new Date().toISOString());
  put('team',{id:'T-asim',name:'Asim',role:'Technician',shift:'General',phone:''});
  put('machines',{id:'591',name:'Pfaff',line:'',location:'Stitching',status:'Breakdown',last:'',next:'',technician:'Asim',department:'Maintenance',notes:'Pfaff machine needle broken'});
}

// ---- sessions / login throttling
const fails=new Map();
function sessionUser(req){const m=/(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie||'');if(!m)return null;
  const r=db.prepare("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.h=? AND s.exp>? AND u.status='active'").get(sha(m[1]),Date.now());return r||null}
const cookie=(v,age)=>`sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${SECURE?'; Secure':''}`;
const SEC={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"};
const send=(res,c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...SEC,...h});res.end(JSON.stringify(o))};
const body=(req,max=1e6)=>new Promise((ok,no)=>{const a=[];let n=0;req.on('data',d=>{n+=d.length;if(n>max){no(new HttpErr(413,'Payload too large'));req.destroy()}else a.push(d)});req.on('end',()=>ok(Buffer.concat(a)));req.on('error',no)});
const jbody=async(req,max)=>{try{return JSON.parse((await body(req,max)).toString()||'{}')}catch(e){if(e instanceof HttpErr)throw e;throw bad('Invalid JSON')}};
const str=(v,n,name,req=false)=>{v=v==null?'':String(v).trim();if(req&&!v)throw bad(name+' is required');if(v.length>n)throw bad(name+' is too long');return v};

// ---- records
function cleanRec(b,id){if(!b||typeof b!=='object'||Array.isArray(b))throw bad('Invalid record');const k=Object.keys(b);if(k.length>60)throw bad('Too many fields');
  for(const x of k){const v=b[x];if(!/^[\w-]{1,40}$/.test(x))throw bad('Invalid field name');if(!(v===null||['string','number','boolean'].includes(typeof v)))throw bad('Invalid value for '+x);if(typeof v==='string'&&v.length>4000)throw bad(x+' is too long')}
  if(typeof b.id!=='string'&&typeof b.id!=='number')throw bad('id is required');b.id=String(b.id).trim();if(!b.id||b.id.length>64)throw bad('Invalid id');if(id!==undefined&&b.id!==id)throw bad('id cannot be changed');return b}
function moveStock(old,n,u){const d=Number(n.stock||0)-Number(old?.stock||0);if(!d)return;const id='MV-'+Date.now()+crypto.randomBytes(2).toString('hex');
  db.prepare("INSERT INTO records(res,id,data,created_by,updated_by,updated_at) VALUES('movements',?,?,?,?,?)").run(id,JSON.stringify({id,part:n.id,name:n.name,delta:d,balance:Number(n.stock||0),by:u.username,ts:new Date().toISOString()}),u.username,u.username,new Date().toISOString())}
function upsert(res,rec,u,mode){const ex=db.prepare('SELECT data FROM records WHERE res=? AND id=?').get(res,rec.id),old=ex&&JSON.parse(ex.data),now=new Date().toISOString();
  if(mode==='add'&&ex)throw new HttpErr(409,`"${rec.id}" already exists`);if(mode==='edit'&&!ex)throw new HttpErr(404,'Record not found');
  if(ex)db.prepare('UPDATE records SET data=?,updated_by=?,updated_at=? WHERE res=? AND id=?').run(JSON.stringify(rec),u.username,now,res,rec.id);
  else db.prepare('INSERT INTO records(res,id,data,created_by,updated_by,updated_at) VALUES(?,?,?,?,?,?)').run(res,rec.id,JSON.stringify(rec),u.username,u.username,now);
  if(res==='spares')moveStock(old,rec,u);return !!ex}

// ---- users
const ASSIGNABLE=['manager','technician','operator','viewer'];
function cleanUser(b,actor,target){const isSuper=actor.role==='super_admin',o={};
  o.full_name=str(b.full_name,80,'Full name',true);o.username=str(b.username,32,'Username',true);if(!/^[A-Za-z0-9_.-]{3,32}$/.test(o.username))throw bad('Username: 3-32 letters, digits, . _ -');
  for(const k of['emp_id','contact','department','hall'])o[k]=str(b[k],100,k);
  o.role=b.role;if(!ROLE[o.role])throw bad('Invalid role');o.status=b.status==='disabled'?'disabled':'active';
  if(!isSuper&&(!ASSIGNABLE.includes(o.role)||(target&&!ASSIGNABLE.includes(target.role))))throw new HttpErr(403,'Only a Super Admin can manage Admin and Super Admin accounts');
  if(b.perms==null||o.role==='super_admin')o.perms=null;else{if(!Array.isArray(b.perms))throw bad('Invalid permissions');o.perms=[...new Set(b.perms.filter(p=>ALLP.includes(p)))];if(!isSuper)for(const p of o.perms)if(!can(actor,p))throw new HttpErr(403,'You cannot grant a permission you do not have: '+p);o.perms=JSON.stringify(o.perms)}
  o.photo=b.photo||'';if(o.photo&&!/^\/uploads\/[a-f0-9]{32}\.(jpg|png|webp)$/.test(o.photo))throw bad('Invalid photo');
  if(b.password||!target){const p=String(b.password||'');if(p.length<10||p.length>200)throw bad('Password must be 10-200 characters');o.pw=hashPw(p)}
  return o}
function lastSuper(t){return t.role==='super_admin'&&t.status==='active'&&db.prepare("SELECT COUNT(*) c FROM users WHERE role='super_admin' AND status='active' AND id!=?").get(t.id).c===0}

// ---- settings
function cleanCfg(b){const c={company:str(b.company,80,'Company name',true),logo:b.logo||'',lists:{},labels:{en:{},ur:{}}};
  if(c.logo&&(!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(c.logo)||c.logo.length>200000))throw bad('Logo must be a PNG/JPEG/WebP under 150 KB');
  for(const k of Object.keys(DEF.lists)){const a=b.lists?.[k];if(!Array.isArray(a)||a.length>200)throw bad('Invalid list '+k);c.lists[k]=[...new Set(a.map(x=>str(x,80,k)).filter(Boolean))]}
  for(const l of['en','ur']){const e=Object.entries(b.labels?.[l]||{});if(e.length>80)throw bad('Too many labels');for(const[k,v]of e){if(!/^[A-Za-z]{1,40}$/.test(k))throw bad('Invalid label key');const s=str(v,80,'Label');if(s)c.labels[l][k]=s}}
  return c}
function usage(old,nw){const out=[];for(const k of Object.keys(old.lists))for(const it of old.lists[k])if(!nw.lists[k].includes(it)){const n=db.prepare("SELECT COUNT(*) c FROM records WHERE res!='movements' AND instr(data,?)>0").get(JSON.stringify(it)).c;if(n)out.push({list:k,item:it,count:n})}return out}

// ---- uploads
const MAGIC=[[[0xff,0xd8,0xff],'jpg'],[[0x89,0x50,0x4e,0x47],'png']];
function imgExt(b){for(const[m,e]of MAGIC)if(m.every((x,i)=>b[i]===x))return e;if(b.slice(0,4).toString()==='RIFF'&&b.slice(8,12).toString()==='WEBP')return'webp';return null}

async function api(req,res,m,p,url,u){
  const q=url.searchParams;
  if(p==='/api/public'&&m==='GET'){const c=getCfg();return send(res,200,{company:c.company,logo:c.logo})}
  if(p==='/api/login'&&m==='POST'){const b=await jbody(req,5e3),un=String(b.username||'').slice(0,64),key=req.socket.remoteAddress+'|'+un.toLowerCase(),f=fails.get(key);
    if(f&&f.until>Date.now())throw new HttpErr(429,'Too many failed attempts. Try again in a few minutes.');
    const r=db.prepare("SELECT * FROM users WHERE username=?").get(un),ok=checkPw(String(b.password||''),r?r.pw:DUMMY)&&r&&r.status==='active';
    if(!ok){const n=(f?.n||0)+1;fails.set(key,{n,until:n>=5?Date.now()+9e5:0});log(un,'login_failed',req.socket.remoteAddress);throw new HttpErr(401,'Invalid username or password')}
    fails.delete(key);db.prepare('DELETE FROM sessions WHERE exp<?').run(Date.now());
    const t=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions(h,user_id,exp) VALUES(?,?,?)').run(sha(t),r.id,Date.now()+288e5);log(un,'login','');
    return send(res,200,pub(r),{'Set-Cookie':cookie(t,28800)})}
  if(!u)throw new HttpErr(401,'Not signed in');
  if(p==='/api/logout'&&m==='POST'){const c=/sid=([a-f0-9]{64})/.exec(req.headers.cookie||'');if(c)db.prepare('DELETE FROM sessions WHERE h=?').run(sha(c[1]));return send(res,200,{ok:1},{'Set-Cookie':cookie('',0)})}
  if(p==='/api/me')return send(res,200,{...pub(u),roles:ROLE,valid:VALID});
  if(p==='/api/settings'){if(m==='GET')return send(res,200,getCfg());
    if(m==='PUT'){need(u,'settings.edit');const old=getCfg(),nw=cleanCfg(await jbody(req,3e5)),use=usage(old,nw);
      if(use.length&&q.get('force')!=='1')throw new HttpErr(409,'Some removed options are used by existing records',use);
      setCfg(nw);log(u.username,'settings_update',use.length?'removed in-use options: '+JSON.stringify(use):'');return send(res,200,nw)}}
  if(p==='/api/users'&&m==='GET'){need(u,'users.view');return send(res,200,db.prepare('SELECT * FROM users ORDER BY id').all().map(pub))}
  if(p==='/api/users'&&m==='POST'){need(u,'users.add');const o=cleanUser(await jbody(req,5e4),u,null);
    try{const r=db.prepare('INSERT INTO users(username,full_name,emp_id,contact,department,hall,role,status,perms,photo,pw) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(o.username,o.full_name,o.emp_id,o.contact,o.department,o.hall,o.role,o.status,o.perms,o.photo,o.pw);
      log(u.username,'user_create',`${o.username} (${o.role})`);return send(res,201,{id:Number(r.lastInsertRowid)})}catch(e){if(/UNIQUE/.test(e.message))throw new HttpErr(409,'Username already exists');throw e}}
  let mu=p.match(/^\/api\/users\/(\d+)$/);
  if(mu){const t=db.prepare('SELECT * FROM users WHERE id=?').get(+mu[1]);if(!t)throw new HttpErr(404,'User not found');
    if(m==='PUT'){need(u,'users.edit');const o=cleanUser(await jbody(req,5e4),u,t);
      if(t.id===u.id&&(o.status!=='active'||o.role!==u.role))throw bad('You cannot disable or change the role of your own account');
      if(lastSuper(t)&&(o.role!=='super_admin'||o.status!=='active'))throw bad('At least one active Super Admin is required');
      const pw=o.pw||t.pw;try{db.prepare('UPDATE users SET username=?,full_name=?,emp_id=?,contact=?,department=?,hall=?,role=?,status=?,perms=?,photo=?,pw=? WHERE id=?').run(o.username,o.full_name,o.emp_id,o.contact,o.department,o.hall,o.role,o.status,o.perms,o.photo,pw,t.id)}catch(e){if(/UNIQUE/.test(e.message))throw new HttpErr(409,'Username already exists');throw e}
      if(o.status!=='active'||o.pw)db.prepare('DELETE FROM sessions WHERE user_id=?').run(t.id);
      log(u.username,'user_update',`${t.username}${o.pw?' (password changed)':''}${o.status!==t.status?' status='+o.status:''}${o.role!==t.role?' role='+o.role:''}`);return send(res,200,{ok:1})}
    if(m==='DELETE'){need(u,'users.delete');if(t.id===u.id)throw bad('You cannot delete your own account');if(q.get('confirm')!==t.username)throw bad('Deletion must be confirmed');
      if(u.role!=='super_admin'&&!ASSIGNABLE.includes(t.role))throw new HttpErr(403,'Only a Super Admin can delete this account');if(lastSuper(t))throw bad('At least one active Super Admin is required');
      db.prepare('DELETE FROM users WHERE id=?').run(t.id);log(u.username,'user_delete',t.username);return send(res,200,{ok:1})}}
  if(p==='/api/audit'&&m==='GET'){need(u,'audit.view');return send(res,200,db.prepare('SELECT ts,user,action,detail FROM audit ORDER BY id DESC LIMIT 300').all())}
  const mr=p.match(/^\/api\/r\/(\w+)(?:\/([^/]+))?$/);
  if(mr){const[,r,rid]=mr,perm=r==='movements'?'spares':r;if(r!=='movements'&&!RES.includes(r))throw new HttpErr(404,'Unknown resource');
    if(m==='GET'&&!rid){need(u,perm+'.view');return send(res,200,db.prepare('SELECT data FROM records WHERE res=? ORDER BY rowid'+(r==='movements'?' DESC LIMIT 500':'')).all(r).map(x=>JSON.parse(x.data)))}
    if(r==='movements')throw new HttpErr(405,'Read only');
    if(m==='POST'&&!rid){need(u,r+'.add');const rec=cleanRec(await jbody(req,1e5));upsert(r,rec,u,'add');log(u.username,r+'_create',rec.id);return send(res,201,rec)}
    if(m==='PUT'&&rid){need(u,r+'.edit');const id=decodeURIComponent(rid),rec=cleanRec(await jbody(req,1e5),id);upsert(r,rec,u,'edit');log(u.username,r+'_update',id);return send(res,200,rec)}
    if(m==='DELETE'&&rid){need(u,r+'.delete');const id=decodeURIComponent(rid),n=db.prepare('DELETE FROM records WHERE res=? AND id=?').run(r,id).changes;if(!n)throw new HttpErr(404,'Record not found');log(u.username,r+'_delete',id);return send(res,200,{ok:1})}}
  if(p==='/api/upload'&&m==='POST'){need(u,q.get('kind')==='profile'?'users.edit':'machines.edit');const b=await body(req,2*1024*1024),e=imgExt(b);if(!e)throw bad('Only JPEG, PNG or WebP images up to 2 MB are allowed');
    const n=crypto.randomBytes(16).toString('hex')+'.'+e;fs.writeFileSync(path.join(DATA,'uploads',n),b);log(u.username,'upload',n);return send(res,201,{url:'/uploads/'+n})}
  if(p==='/api/backup'&&m==='GET'){need(u,'backup.export');const records={};for(const r of[...RES,'movements'])records[r]=db.prepare('SELECT data FROM records WHERE res=? ORDER BY rowid').all(r).map(x=>JSON.parse(x.data));
    log(u.username,'backup_export','');return send(res,200,{app:'DadaFootwearMaintenance',version:3,exportedAt:new Date().toISOString(),settings:getCfg(),records},{'Content-Disposition':'attachment; filename="dada-backup.json"'})}
  if(p==='/api/import'&&m==='POST'){need(u,'backup.import');const b=await jbody(req,2e7);if(b.app!=='DadaFootwearMaintenance')throw bad('Not a Dada Footwear backup file');const src=b.records||b;let n=0;
    db.exec('BEGIN');try{for(const r of RES){if(src[r]==null)continue;if(!Array.isArray(src[r]))throw bad(r+' must be a list');for(const x of src[r]){if(r==='team'&&x&&!x.id)x.id='T-'+crypto.randomBytes(3).toString('hex');upsert(r,cleanRec(x),u,'any');n++}}db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}
    log(u.username,'import',n+' records');return send(res,200,{imported:n})}
  throw new HttpErr(404,'Not found');
}

http.createServer(async(req,res)=>{try{
  const url=new URL(req.url,'http://x'),p=url.pathname,m=req.method;
  if(m!=='GET'&&m!=='HEAD'){if(req.headers['x-requested-with']!=='df')throw new HttpErr(403,'Forbidden');const o=req.headers.origin;if(o&&new URL(o).host!==req.headers.host)throw new HttpErr(403,'Forbidden origin')}
  if(p.startsWith('/api/'))return await api(req,res,m,p,url,sessionUser(req));
  if(p.startsWith('/uploads/')){if(!sessionUser(req))throw new HttpErr(401,'Not signed in');const n=p.slice(9);if(!/^[a-f0-9]{32}\.(jpg|png|webp)$/.test(n))throw new HttpErr(404,'Not found');
    const f=path.join(DATA,'uploads',n);if(!fs.existsSync(f))throw new HttpErr(404,'Not found');res.writeHead(200,{'Content-Type':{jpg:'image/jpeg',png:'image/png',webp:'image/webp'}[n.split('.')[1]],'Cache-Control':'private, max-age=3600',...SEC});return res.end(fs.readFileSync(f))}
  const file={'/':'index.html','/index.html':'index.html','/app.js':'app.js'}[p];if(!file)throw new HttpErr(404,'Not found');
  res.writeHead(200,{'Content-Type':file.endsWith('.js')?'text/javascript; charset=utf-8':'text/html; charset=utf-8','Cache-Control':'no-cache',...SEC});res.end(fs.readFileSync(path.join(PUB,file)));
}catch(e){if(e instanceof HttpErr)return send(res,e.c,{error:e.message,usage:e.x});console.error(e);send(res,500,{error:'Server error'})}}).listen(PORT,()=>console.log('Dada Footwear Maintenance running on http://localhost:'+PORT));
