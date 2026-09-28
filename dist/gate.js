/* Unlock a small entry page; decrypt individual assets only when requested. */
'use strict';
(() => {
  const form = document.querySelector('#unlock-form'), input = document.querySelector('#access-password');
  const button = document.querySelector('#unlock'), status = document.querySelector('#gate-status');
  const encoder = new TextEncoder(), decoder = new TextDecoder(), FORMAT = 'ego23-vault-v2';
  const base = new URL('./', location.href).href;
  const fromBase64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const hash = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(n => n.toString(16).padStart(2,'0')).join('');
  const message = (text, error = false) => {status.textContent = text;status.classList.toggle('error',error);};
  let active = 0;
  const queue = [], controllers = new Set();
  async function limited(operation) {
    if (active >= 4) await new Promise(resolve => queue.push(resolve));
    active++;
    try {return await operation();} finally {active--;queue.shift()?.();}
  }
  async function readPart(part, isOpen = () => true) {
    if (!/^asset-[a-f0-9]{64}\.bin$/.test(part.file) || part.bytes > 1024 * 1024 || part.bytes <= 0) throw new Error('页面资源索引无效，请刷新。');
    return limited(async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        if (!isOpen()) throw new Error('访问已退出。');
        const controller = new AbortController();controllers.add(controller);
        const timer = setTimeout(() => controller.abort(),20000);
        try {
          const response = await fetch(new URL(part.file,base),{signal:controller.signal});
          if (!response.ok) throw new Error('内容下载失败');
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (bytes.length !== part.bytes || await hash(bytes) !== part.sha256) throw new Error('内容校验失败');
          return bytes;
        } catch (error) {
          if (attempt === 2 || !isOpen()) throw new Error('网络读取超时或内容不完整，请重试。');
        } finally {clearTimeout(timer);controllers.delete(controller);}
      }
    });
  }
  async function unpack(key, record, identity, isOpen) {
    const parts = await Promise.all(record.parts.map(part => readPart(part,isOpen)));
    const encrypted = new Uint8Array(parts.reduce((size,part) => size + part.length,0));
    let offset = 0;for (const part of parts) {encrypted.set(part,offset);offset += part.length;}
    if (await hash(encrypted) !== record.sha256) throw new Error('内容校验失败，请重试。');
    let compressed;
    try {compressed = await crypto.subtle.decrypt({name:'AES-GCM',iv:fromBase64(record.iv),additionalData:encoder.encode(FORMAT+':'+identity)},key,encrypted);}
    catch {throw new Error(identity === 'core' ? '密码不正确，请重新输入。' : '资源验证失败，请重新打开主页。');}
    const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  async function prepareWorker() {
    await navigator.serviceWorker.register(new URL('vault-worker.js',base),{scope:base,updateViaCache:'none'});
    await navigator.serviceWorker.ready;
    if (navigator.serviceWorker.controller) return;
    await new Promise((resolve,reject) => {
      const timer = setTimeout(() => {navigator.serviceWorker.removeEventListener('controllerchange',done);reject(new Error('浏览器未能准备媒体加载，请刷新重试。'));},12000);
      const done = () => {if(navigator.serviceWorker.controller){clearTimeout(timer);navigator.serviceWorker.removeEventListener('controllerchange',done);resolve();}};
      navigator.serviceWorker.addEventListener('controllerchange',done);done();
    });
  }
  function createLoader(key, assets) {
    const token = [...crypto.getRandomValues(new Uint8Array(24))].map(n=>n.toString(16).padStart(2,'0')).join('');
    const cache = new Map(), pending = new Map(), downloads = new Set(), watched = new WeakSet();
    let size = 0, open = true, observer;
    const load = async path => {
      if (!open || !Object.hasOwn(assets,path)) throw new Error('资源不存在或访问已退出。');
      if (cache.has(path)) {const data=cache.get(path);cache.delete(path);cache.set(path,data);return data;}
      if (!pending.has(path)) pending.set(path,unpack(key,assets[path],path,()=>open).then(data => {
        if (!open) throw new Error('访问已退出。');
        cache.set(path,data);size += data.byteLength;
        while(size > 64*1024*1024 && cache.size > 1) {const first=cache.keys().next().value;size-=cache.get(first).byteLength;cache.delete(first);}
        return data;
      }).finally(() => pending.delete(path)));
      return pending.get(path);
    };
    const receive = async event => {
      const request=event.data, port=event.ports[0];
      if (request?.type !== 'ego23-private-request' || request.token !== token || !port) return;
      // Acknowledge ownership immediately; the worker need not keep session state.
      port.postMessage({accepted:true});
      try {
        const data=await load(request.path), total=data.byteLength;
        let start=0,end=total-1,statusCode=200;
        const headers={'Content-Type':assets[request.path].mime,'Cache-Control':'no-store','Accept-Ranges':'bytes'};
        if(request.range) {
          const match=/^bytes=(\d*)-(\d*)$/.exec(request.range);
          if(!match || (!match[1] && !match[2])) throw new Error('无效的播放范围');
          start=match[1]?Number(match[1]):Math.max(0,total-Number(match[2]));
          end=match[1]&&match[2]?Math.min(total-1,Number(match[2])):total-1;
          if(start>end || start>=total) {port.postMessage({status:416,headers:{'Content-Range':`bytes */${total}`},body:new ArrayBuffer(0)});return;}
          statusCode=206;headers['Content-Range']=`bytes ${start}-${end}/${total}`;
        }
        headers['Content-Length']=String(end-start+1);
        const body=request.method==='HEAD'?new ArrayBuffer(0):data.slice(start,end+1).buffer;
        if(!open) throw new Error('访问已退出。');
        port.postMessage({status:statusCode,headers,body},[body]);
      } catch {port.postMessage({status:open?503:403,headers:{'Cache-Control':'no-store'},body:new ArrayBuffer(0)});}
    };
    const downloadClick = async event => {
      const link=event.target.closest('a[download]');
      const prefix=new URL('__vault_asset__/'+token+'/',base).href;
      if(!link?.href.startsWith(prefix))return;
      event.preventDefault();link.setAttribute('aria-busy','true');
      try {
        const path=decodeURIComponent(link.href.slice(prefix.length)), data=await load(path);
        if(!open)return;
        // Browser download navigation can bypass service workers; use a local blob.
        const url=URL.createObjectURL(new Blob([data],{type:assets[path].mime}));downloads.add(url);
        const save=document.createElement('a');save.href=url;save.download=link.download||path.split('/').pop();
        document.body.append(save);save.click();save.remove();
        setTimeout(()=>{URL.revokeObjectURL(url);downloads.delete(url);},60000);
      } catch {link.title='下载未完成，请点击重试。';}
      finally {link.removeAttribute('aria-busy');}
    };
    const attachDownloads = doc => {
      if(watched.has(doc))return;watched.add(doc);doc.addEventListener('click',downloadClick,true);
    };
    const watchFrames = () => document.querySelectorAll('iframe').forEach(frame=>{
      if(watched.has(frame))return;watched.add(frame);
      frame.addEventListener('load',()=>{try{if(frame.contentDocument)attachDownloads(frame.contentDocument);}catch{}});
    });
    return {
      url:path=>new URL('__vault_asset__/'+token+'/'+encodeURIComponent(path),base).href,
      connect(){navigator.serviceWorker.addEventListener('message',receive);attachDownloads(document);observer=new MutationObserver(watchFrames);observer.observe(document.documentElement,{childList:true,subtree:true});watchFrames();},
      close(){open=false;key=null;cache.clear();pending.clear();controllers.forEach(c=>c.abort());downloads.forEach(URL.revokeObjectURL);observer?.disconnect();navigator.serviceWorker.removeEventListener('message',receive);},
    };
  }
  function openContent(bundle,key) {
    const files = new Map(bundle.files.map(file=>[file.path,file]));
    if(!files.has('index.html') || !files.has('assets/app.js')) throw new Error('页面内容不完整。');
    const loader=createLoader(key,bundle.assets), urls={};
    const bytes=file=>fromBase64(file.data), text=path=>decoder.decode(bytes(files.get(path)));
    for(const path of Object.keys(bundle.assets)) urls[path]=loader.url(path);
    for(const [path,file] of files) if(path!=='index.html'&&!path.endsWith('.css')) urls[path]=URL.createObjectURL(new Blob([bytes(file)],{type:file.mime}));
    for(const [path,file] of files) {
      if(!path.endsWith('.css')) continue;
      const rewritten=text(path).replace(/url\((['"]?)([^)'"\s]+)\1\)/g,(match,quote,ref)=>{
        const resolved=new URL(ref,'https://assets.invalid/'+path).pathname.slice(1);
        return urls[resolved]?`url("${urls[resolved]}")`:match;
      });
      urls[path]=URL.createObjectURL(new Blob([rewritten],{type:file.mime}));
    }
    let html=text('index.html').replace(/\b(src|poster|href)=(['"])(.*?)\2/g,(match,attr,quote,ref)=>urls[ref]?`${attr}=${quote}${urls[ref]}${quote}`:match);
    // document.open removes window listeners; reconnect inside the new document.
    window.__EGO23_PRIVATE_VAULT__=loader;
    const map=JSON.stringify(urls).replace(/</g,'\\u003c');
    const bootstrap=`<script>window.__EGO23_ASSET_URLS__=${map};window.__EGO23_PRIVATE_VAULT__.connect();window.addEventListener('pageshow',e=>{if(e.persisted)location.reload();});window.addEventListener('pagehide',()=>window.__EGO23_PRIVATE_VAULT__?.close());document.addEventListener('DOMContentLoaded',()=>{const nav=document.querySelector('.topbar nav');if(nav){const a=document.createElement('a');a.id='lock-page';a.href=location.pathname;a.textContent='退出访问';a.addEventListener('click',e=>{e.preventDefault();window.__EGO23_PRIVATE_VAULT__?.close();document.querySelectorAll('video').forEach(v=>{v.pause();v.removeAttribute('src');v.removeAttribute('poster');v.load();});document.querySelectorAll('iframe').forEach(f=>f.remove());Object.values(window.__EGO23_ASSET_URLS__||{}).filter(u=>u.startsWith('blob:')).forEach(URL.revokeObjectURL);delete window.__EGO23_ASSET_URLS__;delete window.__EGO23_PRIVATE_VAULT__;document.body.replaceChildren();location.replace(location.pathname);});nav.append(a);}});<\/script>`;
    html=html.replace('<head>','<head>'+bootstrap);
    document.open();document.write(html);document.close();
  }
  if(!crypto.subtle || typeof DecompressionStream==='undefined' || !('serviceWorker' in navigator)) {
    message('请通过 HTTPS 在较新版本的 Chrome、Edge 或 Safari 中打开。',true);return;
  }
  message('');button.disabled=false;
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(button.disabled)return;
    const password=input.value.trim();if(!password)return;
    button.disabled=true;message('正在打开主页，视频将按需载入…');
    try {
      const response=await fetch('vault.json?build='+encodeURIComponent(document.body.dataset.build),{cache:'no-store',signal:AbortSignal.timeout(20000)});
      if(!response.ok)throw new Error('无法读取主页，请重试。');
      const manifest=await response.json();
      if(manifest.format!==FORMAT || manifest.iterations!==600000)throw new Error('页面已更新，请刷新重试。');
      const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);
      const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:fromBase64(manifest.salt),iterations:manifest.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
      const bundle=JSON.parse(decoder.decode(await unpack(key,manifest.core,'core')));
      await prepareWorker();input.value='';openContent(bundle,key);
    } catch(error){message(error.message||'打开失败，请重试。',true);input.value='';input.focus();button.disabled=false;}
  });
})();
