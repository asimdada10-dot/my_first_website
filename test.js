// Acceptance tests: node test.js   (starts its own server on a temp database)
const {spawn,execFileSync}=require('node:child_process'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const D=fs.mkdtempSync(path.join(os.tmpdir(),'dada-')),PORT=3900+Math.floor(Math.random()*90),B='http://localhost:'+PORT,ENV={...process.env,DATA_DIR:D,PORT,ADMIN_PASSWORD:'SuperSecret-123'};
let srv,pass=0,fail=0;const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const start=async()=>{srv=spawn('node',['server.js'],{env:ENV,stdio:'ignore'});for(let i=0;i<50;i++){try{await fetch(B+'/api/public');return}catch{await sleep(100)}}throw Error('server did not start')};
const stop=async()=>{srv.kill();await sleep(300)};
class C{constructor(){this.c=''}async go(m,u,b,h={}){const r=await fetch(B+u,{method:m,headers:{'X-Requested-With':'df',...(b&&typeof b==='object'&&!Buffer.isBuffer(b)?{'Content-Type':'application/json'}:{}),...(this.c?{Cookie:this.c}:{}),...h},body:b?(Buffer.isBuffer(b)?b:JSON.stringify(b)):undefined});const sc=r.headers.get('set-cookie');if(sc)this.c=sc.split(';')[0];const t=await r.text();let j;try{j=JSON.parse(t)}catch{j=t}return{s:r.status,j}}}
const ok=(n,c)=>{c?pass++:fail++;console.log((c?'PASS ':'FAIL ')+n)};
(async()=>{await start();const A=new C();
 ok('unauthenticated API is rejected',(await new C().go('GET','/api/r/machines')).s===401);
 ok('static page served, no demo credentials in it',await(async()=>{const h=await(await fetch(B+'/')).text();return h.includes('loginForm')&&!/dada123|tech123/.test(h)})());
 ok('wrong password rejected',(await A.go('POST','/api/login',{username:'admin',password:'nope'})).s===401);
 const l=await A.go('POST','/api/login',{username:'admin',password:'SuperSecret-123'});ok('Super Admin login works, no password in response',l.s===200&&!JSON.stringify(l.j).includes('pw')&&l.j.role==='super_admin');
 const m0=await A.go('GET','/api/r/machines');ok('initial example data (Pfaff 591, Stitching, Asim) present',m0.j.some(m=>m.id==='591'&&m.name==='Pfaff'&&m.location==='Stitching'&&m.technician==='Asim'&&/needle broken/.test(m.notes)));
 const nu=await A.go('POST','/api/users',{full_name:'Tariq Viewer',username:'tariq',password:'tariq-pass-123',role:'operator',status:'active',perms:['machines.view','spares.view']});ok('add user with specific permissions',nu.s===201);
 const U=new C();await U.go('POST','/api/login',{username:'tariq',password:'tariq-pass-123'});
 ok('restricted user can view permitted pages',(await U.go('GET','/api/r/machines')).s===200);
 ok('restricted user cannot add machines (server-side)',(await U.go('POST','/api/r/machines',{id:'X1',name:'x'})).s===403);
 ok('restricted user cannot read orders / users / audit / backup',(await U.go('GET','/api/r/orders')).s===403&&(await U.go('GET','/api/users')).s===403&&(await U.go('GET','/api/audit')).s===403&&(await U.go('GET','/api/backup')).s===403);
 ok('CSRF: mutation without header is blocked',(await fetch(B+'/api/logout',{method:'POST'})).status===403);
 ok('add machine',(await A.go('POST','/api/r/machines',{id:'600',name:'Juki',location:'Stitching',status:'Running'})).s===201);
 ok('duplicate machine code rejected',(await A.go('POST','/api/r/machines',{id:'600',name:'Dup'})).s===409);
 ok('edit machine',(await A.go('PUT','/api/r/machines/600',{id:'600',name:'Juki DDL',status:'Idle'})).s===200);
 ok('SQL-injection style id handled safely',(await A.go('POST','/api/r/machines',{id:"x'); DROP TABLE records;--",name:'t'})).s===201&&(await A.go('GET','/api/r/machines')).j.length>=3);
 ok('invalid payload rejected',(await A.go('POST','/api/r/machines',{id:'9',name:{a:1}})).s===400);
 await A.go('POST','/api/r/spares',{id:'SP-1',name:'Needle',stock:10,min:3,unit:'Piece'});await A.go('PUT','/api/r/spares/SP-1',{id:'SP-1',name:'Needle',stock:7,min:3,unit:'Piece'});
 const mv=await A.go('GET','/api/r/movements');ok('inventory movement history recorded',mv.j.length===2&&mv.j[0].delta===-3);
 ok('delete machine',(await A.go('DELETE','/api/r/machines/600')).s===200);
 // non-super admin limits
 await A.go('POST','/api/users',{full_name:'Adm',username:'adm',password:'adm-password-1',role:'admin',status:'active'});const M=new C();await M.go('POST','/api/login',{username:'adm',password:'adm-password-1'});
 ok('Admin cannot create Admin/Super Admin',(await M.go('POST','/api/users',{full_name:'x',username:'evil',password:'evil-password-1',role:'super_admin',status:'active'})).s===403);
 ok('Admin cannot grant permissions it lacks',(await M.go('POST','/api/users',{full_name:'x',username:'evil2',password:'evil-password-1',role:'viewer',status:'active',perms:['users.delete']})).s===403);
 // revoke access
 const us=(await A.go('GET','/api/users')).j,tid=us.find(u=>u.username==='tariq').id;
 ok('disable user -> existing session dies immediately',(await A.go('PUT','/api/users/'+tid,{...us.find(u=>u.username==='tariq'),status:'disabled',perms:['machines.view']})).s===200&&(await U.go('GET','/api/r/machines')).s===401);
 ok('disabled user cannot log in',(await new C().go('POST','/api/login',{username:'tariq',password:'tariq-pass-123'})).s===401);
 await A.go('PUT','/api/users/'+tid,{...us.find(u=>u.username==='tariq'),status:'active',perms:['machines.view'],password:'new-password-123'});
 ok('password change works and old password stops working',(await new C().go('POST','/api/login',{username:'tariq',password:'tariq-pass-123'})).s===401&&(await new C().go('POST','/api/login',{username:'tariq',password:'new-password-123'})).s===200);
 const U2=new C();await U2.go('POST','/api/login',{username:'tariq',password:'new-password-123'});
 ok('delete requires confirmation',(await A.go('DELETE','/api/users/'+tid)).s===400);
 ok('delete user revokes access',(await A.go('DELETE','/api/users/'+tid+'?confirm=tariq')).s===200&&(await U2.go('GET','/api/r/machines')).s===401);
 const me=(await A.go('GET','/api/me')).j;ok('cannot delete/disable the only Super Admin or yourself',(await A.go('DELETE','/api/users/'+me.id+'?confirm=admin')).s===400&&(await A.go('PUT','/api/users/'+me.id,{...me,status:'disabled',perms:null})).s===400);
 // settings
 const cfg=(await A.go('GET','/api/settings')).j;cfg.company='Dada Footwear Pvt';cfg.lists.halls=cfg.lists.halls.filter(h=>h!=='Stitching');
 const s1=await A.go('PUT','/api/settings',cfg);ok('warn before removing an option used by records',s1.s===409&&s1.j.usage.some(u=>u.item==='Stitching'&&u.count>=1));
 ok('force save + rename company',(await A.go('PUT','/api/settings?force=1',cfg)).s===200&&(await A.go('GET','/api/public')).j.company==='Dada Footwear Pvt');
 ok('Admin role may edit settings (by design); permission is server-checked',(await M.go('PUT','/api/settings',cfg)).s===200); // admin has settings.edit by design
 // uploads
 const png=Buffer.concat([Buffer.from([0x89,0x50,0x4e,0x47,13,10,26,10]),Buffer.alloc(50)]);const up=await A.go('POST','/api/upload?kind=machine',png,{'Content-Type':'application/octet-stream'});
 ok('valid image upload',up.s===201&&/^\/uploads\/[a-f0-9]{32}\.png$/.test(up.j.url));
 ok('fake image (text) rejected',(await A.go('POST','/api/upload',Buffer.from('<script>alert(1)</script>'),{'Content-Type':'image/png'})).s===400);
 ok('uploads need login; path traversal blocked',(await fetch(B+up.j.url)).status===401&&(await A.go('GET','/uploads/..%2Fapp.db')).s===404);
 // audit + backup
 const au=(await A.go('GET','/api/audit')).j;ok('audit log records important changes',['user_create','user_delete','login_failed','settings_update'].every(a=>au.some(r=>r.action===a)));
 const bk=(await A.go('GET','/api/backup')).j;ok('JSON backup has records, no password hashes',bk.records.machines.length>=2&&!JSON.stringify(bk).includes('s1$'));
 ok('import validates and restores records',(await A.go('POST','/api/import',{app:'DadaFootwearMaintenance',records:{machines:[{id:'IMP1',name:'Imported'}]}})).j.imported===1&&(await A.go('POST','/api/import',{app:'x'})).s===400);
 // throttling
 const T=new C();let last;for(let i=0;i<6;i++)last=await T.go('POST','/api/login',{username:'admin',password:'bad'+i});ok('login lockout after repeated failures',last.s===429);
 // persistence across restart + DB backup/restore
 await stop();await start();const P=new C();await P.go('POST','/api/login',{username:'admin',password:'SuperSecret-123'});
 ok('records persist after restart',(await P.go('GET','/api/r/machines')).j.some(m=>m.id==='591')&&(await P.go('GET','/api/r/machines')).j.some(m=>m.id==='IMP1'));
 await stop();const bf=path.join(D,'b.db');execFileSync('node',['server.js','backup',bf],{env:ENV});await start();const R=new C();await R.go('POST','/api/login',{username:'admin',password:'SuperSecret-123'});await R.go('DELETE','/api/r/machines/591');await stop();
 execFileSync('node',['server.js','restore',bf],{env:ENV});await start();const R2=new C();await R2.go('POST','/api/login',{username:'admin',password:'SuperSecret-123'});
 ok('database backup + restore brings deleted data back',(await R2.go('GET','/api/r/machines')).j.some(m=>m.id==='591'));
 await stop();console.log(`\n${pass} passed, ${fail} failed`);process.exit(fail?1:0)})().catch(e=>{console.error(e);srv&&srv.kill();process.exit(1)});
