export async function onRequest({params,env}){
  const r=await env.DB.prepare('UPDATE projects SET clicks=clicks+1 WHERE id=? RETURNING url').bind(params.id).first();
  return r?Response.redirect(r.url,302):new Response('Introuvable',{status:404});
}
