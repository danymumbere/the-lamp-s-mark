const J=(d,s=200,h={})=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json',...h}});
const enc=new TextEncoder();
async function sign(v,k){const key=await crypto.subtle.importKey('raw',enc.encode(k),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(v)))].map(b=>b.toString(16).padStart(2,'0')).join('')}
async function authed(req,env){const m=(req.headers.get('cookie')||'').match(/lm=(\d+)\.([a-f0-9]+)/);
  return !!m&&Date.now()<+m[1]&&await sign(m[1],env.ADMIN_PASSWORD)===m[2]}
const dec=s=>s.replace(/&amp;/g,'&').replace(/&#0?39;|&#x27;/g,"'").replace(/&quot;/g,'"');
async function og(url){
  const r=await fetch(url,{headers:{'user-agent':'Mozilla/5.0 (compatible; LambsMarkBot/1.0)'},redirect:'follow'});
  const h=(await r.text()).slice(0,300000);
  const meta=n=>{const t=h.match(new RegExp(`<meta[^>]+(?:property|name)=["']${n}["'][^>]*>`,'i'));
    const c=t&&t[0].match(/content=["']([^"']*)["']/i);return c?dec(c[1]):''};
  let image=meta('og:image');try{if(image)image=new URL(image,url).href}catch{}
  return{title:(meta('og:title')||dec((h.match(/<title[^>]*>([^<]*)/i)||[])[1]||'')).trim(),
    description:meta('og:description')||meta('description'),image};
}
export async function onRequest({request:req,env,params}){
  const p='/'+[].concat(params.path||[]).join('/'),m=req.method,db=env.DB;
  const body=()=>req.json().catch(()=>({}));let x;
  if(p==='/login'&&m==='POST'){
    const b=await body();if(!env.ADMIN_PASSWORD||b.password!==env.ADMIN_PASSWORD)return J({error:'Mot de passe incorrect'},401);
    const exp=Date.now()+6048e5;
    return J({ok:1},200,{'set-cookie':`lm=${exp}.${await sign(String(exp),env.ADMIN_PASSWORD)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`});
  }
  if(p==='/projects'&&m==='GET'){
    const {results}=await db.prepare(`SELECT p.id,p.title,p.description,p.image,p.goal,COALESCE((SELECT SUM(amount) FROM donations WHERE project_id=p.id AND status='confirmed'),0) raised FROM projects p ORDER BY p.id DESC`).all();
    return J(results,200,{'cache-control':'public,max-age=60'});
  }
  if((x=p.match(/^\/donations\/(\d+)$/))&&m==='GET'){
    const {results}=await db.prepare(`SELECT substr(created,1,10) d,SUM(amount) a,COUNT(*) n FROM donations WHERE project_id=? AND status='confirmed' GROUP BY d ORDER BY d`).bind(x[1]).all();
    return J(results);
  }
  if(p==='/donate'&&m==='POST'){
    const b=await body(),a=+b.amount;
    if(!(a>0&&a<1e6)||!b.ref||String(b.ref).length>60)return J({error:'Montant ou référence invalide'},400);
    if(!await db.prepare('SELECT 1 FROM projects WHERE id=?').bind(b.project_id).first())return J({error:'Projet inconnu'},404);
    await db.prepare('INSERT INTO donations(project_id,name,phone,ref,amount) VALUES(?,?,?,?,?)').bind(b.project_id,String(b.name||'Anonyme').slice(0,60),String(b.phone||'').slice(0,20),String(b.ref).slice(0,60),a).run();
    return J({ok:1});
  }
  if((x=p.match(/^\/img\/(\d+)$/))&&m==='GET'){
    const r=await db.prepare('SELECT data FROM images WHERE id=?').bind(x[1]).first();if(!r)return new Response('',{status:404});
    const [h,d]=r.data.split(',');const bin=atob(d),u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);
    return new Response(u,{headers:{'content-type':h.match(/:(.*);/)[1],'cache-control':'public,max-age=31536000'}});
  }
  if(!await authed(req,env))return J({error:'auth'},401);
  if(p==='/og'){try{const u=new URL(new URL(req.url).searchParams.get('url'));if(!/^https?:$/.test(u.protocol))throw 0;return J(await og(u.href))}catch{return J({error:'Lien illisible'},400)}}
  if(p==='/admin/projects'&&m==='GET')return J((await db.prepare('SELECT * FROM projects ORDER BY id DESC').all()).results);
  if(p==='/admin/projects'&&m==='POST'){
    const b=await body();if(!/^https?:\/\//.test(b.url||''))return J({error:'Lien invalide'},400);
    let img=b.image||'';
    if(b.imageData){if(!/^data:image\/(jpeg|png|webp);base64,/.test(b.imageData))return J({error:'Image invalide'},400);
      img='/api/img/'+(await db.prepare('INSERT INTO images(data) VALUES(?)').bind(b.imageData).run()).meta.last_row_id}
    if(b.id)await db.prepare('UPDATE projects SET title=?,description=?,url=?,image=?,goal=? WHERE id=?').bind(b.title,b.description,b.url,img,+b.goal||0,b.id).run();
    else await db.prepare('INSERT INTO projects(title,description,url,image,goal) VALUES(?,?,?,?,?)').bind(b.title,b.description,b.url,img,+b.goal||0).run();
    return J({ok:1});
  }
  if((x=p.match(/^\/admin\/projects\/(\d+)$/))&&m==='DELETE'){await db.prepare('DELETE FROM projects WHERE id=?').bind(x[1]).run();return J({ok:1})}
  if(p==='/admin/donations'&&m==='GET')return J((await db.prepare('SELECT d.*,p.title project FROM donations d LEFT JOIN projects p ON p.id=d.project_id ORDER BY d.id DESC LIMIT 300').all()).results);
  if((x=p.match(/^\/admin\/donations\/(\d+)$/))&&m==='POST'){const b=await body();
    if(!['confirmed','rejected','pending'].includes(b.status))return J({error:'?'},400);
    await db.prepare('UPDATE donations SET status=? WHERE id=?').bind(b.status,x[1]).run();return J({ok:1})}
  return J({error:'Introuvable'},404);
}
