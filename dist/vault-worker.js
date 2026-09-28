/* No keys, passwords, decrypted files or persistent caches live in this worker. */
'use strict';
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url), prefix=new URL('__vault_asset__/',self.registration.scope).pathname;
  if(url.origin!==self.location.origin || !url.pathname.startsWith(prefix))return;
  event.respondWith((async()=>{
    const [token,...tail]=url.pathname.slice(prefix.length).split('/');
    if(!/^[a-f0-9]{48}$/.test(token)||!['GET','HEAD'].includes(event.request.method))return new Response('Locked',{status:403});
    let path;try{path=decodeURIComponent(tail.join('/'));}catch{return new Response('Invalid path',{status:400});}
    const clients=await self.clients.matchAll({type:'window',includeUncontrolled:true});
    if(!clients.length)return new Response('Locked',{status:403});
    try {
      // Rediscover the unlocked page after worker termination; no stored session is needed.
      return await Promise.any(clients.map(client=>new Promise((resolve,reject)=>{
        const channel=new MessageChannel();let timer;
        const timeout=ms=>{clearTimeout(timer);timer=setTimeout(()=>{channel.port1.close();reject(new Error('Unavailable'));},ms);};
        timeout(2000);
        channel.port1.onmessage=message=>{
          const reply=message.data;
          if(reply.accepted){timeout(180000);return;}
          clearTimeout(timer);channel.port1.close();
          resolve(new Response(event.request.method==='HEAD'?null:reply.body,{status:reply.status,headers:reply.headers}));
        };
        client.postMessage({type:'ego23-private-request',token,path,range:event.request.headers.get('range'),method:event.request.method},[channel.port2]);
      })));
    } catch {return new Response('Please unlock the homepage again.',{status:403,headers:{'Cache-Control':'no-store'}});}
  })());
});
