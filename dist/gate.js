/* Decrypt the complete publication locally; no password is sent or persisted. */
'use strict';
(() => {
  const form = document.querySelector('#unlock-form');
  const input = document.querySelector('#access-password');
  const button = document.querySelector('#unlock');
  const status = document.querySelector('#gate-status');
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const aad = encoder.encode('ego23-vault-v1');
  let download;
  const fromBase64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const message = (text, error = false) => { status.textContent = text; status.classList.toggle('error', error); };

  async function loadVault() {
    if (!download) download = (async () => {
      const meta = await fetch('vault.json?build=' + encodeURIComponent(document.body.dataset.build), {cache:'no-store'});
      if (!meta.ok) throw new Error('无法读取页面，请稍后重试。');
      const manifest = await meta.json();
      if (manifest.format !== 'ego23-vault-v1' || manifest.iterations !== 600000 || !/^content-[a-f0-9]{20}\.bin$/.test(manifest.payload)) throw new Error('页面版本不匹配，请刷新重试。');
      const response = await fetch(manifest.payload);
      if (!response.ok) throw new Error('内容下载失败，请重试。');
      const encrypted = await response.arrayBuffer();
      const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', encrypted))].map(n=>n.toString(16).padStart(2,'0')).join('');
      if (digest !== manifest.sha256) throw new Error('下载内容不完整，请刷新重试。');
      return {manifest, encrypted};
    })().catch(error => { download = null; throw error; });
    return download;
  }

  async function decrypt(password, manifest, encrypted) {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      {name:'PBKDF2', salt:fromBase64(manifest.salt), iterations:manifest.iterations, hash:'SHA-256'},
      material, {name:'AES-GCM', length:256}, false, ['decrypt'],
    );
    let compressed;
    try {
      compressed = await crypto.subtle.decrypt({name:'AES-GCM', iv:fromBase64(manifest.iv), additionalData:aad, tagLength:128}, key, encrypted);
    } catch { throw new Error('密码不正确，请重新输入。'); }
    const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
    return JSON.parse(await new Response(stream).text());
  }

  function openContent(bundle) {
    const files = new Map(bundle.files.map(file => [file.path, file]));
    if (!files.has('index.html') || !files.has('assets/app.js')) throw new Error('页面内容不完整。');
    const urls = {};
    const bytes = file => fromBase64(file.data);
    const text = path => decoder.decode(bytes(files.get(path)));
    for (const [path, file] of files) {
      if (path !== 'index.html' && !path.endsWith('.css')) urls[path] = URL.createObjectURL(new Blob([bytes(file)], {type:file.mime}));
    }
    for (const [path, file] of files) {
      if (!path.endsWith('.css')) continue;
      const rewritten = text(path).replace(/url\((['"]?)([^)'"\s]+)\1\)/g, (match, quote, reference) => {
        const resolved = new URL(reference, 'https://assets.invalid/' + path).pathname.slice(1);
        return urls[resolved] ? `url("${urls[resolved]}")` : match;
      });
      urls[path] = URL.createObjectURL(new Blob([rewritten], {type:file.mime}));
    }
    let html = text('index.html').replace(/\b(src|poster|href)=(['"])(.*?)\2/g, (match, attribute, quote, reference) => urls[reference] ? `${attribute}=${quote}${urls[reference]}${quote}` : match);
    const safeMap = JSON.stringify(urls).replace(/</g, '\\u003c');
    const bootstrap = `<script>window.__EGO23_ASSET_URLS__=${safeMap};window.addEventListener('pageshow',e=>{if(e.persisted)location.reload();});document.addEventListener('DOMContentLoaded',()=>{const nav=document.querySelector('.topbar nav');if(nav){const a=document.createElement('a');a.id='lock-page';a.href=location.pathname;a.textContent='退出访问';a.addEventListener('click',e=>{e.preventDefault();Object.values(window.__EGO23_ASSET_URLS__||{}).forEach(URL.revokeObjectURL);delete window.__EGO23_ASSET_URLS__;document.body.replaceChildren();location.replace(location.pathname);});nav.append(a);}});<\/script>`;
    html = html.replace('<head>', '<head>' + bootstrap);
    document.open(); document.write(html); document.close();
  }

  if (!crypto.subtle || typeof DecompressionStream === 'undefined') {
    message('请使用较新版本的 Chrome、Edge 或 Safari，并通过 HTTPS 打开。', true);
    return;
  }
  message(''); button.disabled = false;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (button.disabled) return;
    const password = input.value.trim();
    if (!password) return;
    button.disabled = true; message('正在验证并载入内容…');
    try {
      const {manifest, encrypted} = await loadVault();
      const bundle = await decrypt(password, manifest, encrypted);
      input.value = ''; download = null;
      openContent(bundle);
    } catch (error) {
      message(error.message || '打开失败，请重试。', true);
      input.value = ''; input.focus(); button.disabled = false;
    }
  });
})();
