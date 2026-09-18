const VERSION='wifi-vault-v3';
const ASSETS=['./','./index.html','./css/style.css','./js/app.js','./manifest.json'];
self.addEventListener('install',event=>event.waitUntil(caches.open(VERSION).then(cache=>cache.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==VERSION).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{if(event.request.method!=='GET')return;event.respondWith(caches.match(event.request).then(cached=>cached||fetch(event.request).then(response=>{if(new URL(event.request.url).origin===location.origin){let copy=response.clone();caches.open(VERSION).then(c=>c.put(event.request,copy))}return response}).catch(()=>caches.match('./index.html')))});
