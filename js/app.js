/* Wi-Fi Vault application. Deliberately self-contained: no ES modules. */
(function () {
  'use strict';

  var STORAGE_KEY = 'kdbx_binary_store';
  var GITHUB_CONFIG_KEY = 'wifi_vault_github_cfg';
  var SHA_KEY = 'kdbx_github_sha';
  var activeDb = null, vaultData = [], activeFilter = 'all', editTargetId = null;
  var activeCoordinates = null, videoStream = null, qrScanInterval = null;

  function text(value) {
    if (value === null || value === undefined) return '';
    if (typeof value.getText === 'function') return value.getText();
    return String(value);
  }
  function b64(buffer) {
    var bytes = new Uint8Array(buffer), out = '';
    for (var i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(out);
  }
  function fromB64(value) {
    var raw = atob(String(value).replace(/\s/g, '')), bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }
  function esc(value) { return text(value).replace(/[&<>'"]/g, function (c) { return ({ '&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;' })[c]; }); }
  function idFor(entry) { return entry.uuid && (entry.uuid.id || entry.uuid.toString()); }
  function errorMessage(error) { return error && error.message ? error.message : String(error || 'Unknown error'); }
  function setHidden(element, hidden) { if (element) element.classList.toggle('hidden', !!hidden); }

  async function persistActiveDb() {
    if (!activeDb) return;
    localStorage.setItem(STORAGE_KEY, b64(await activeDb.save()));
  }
  function storedBuffer() { var value = localStorage.getItem(STORAGE_KEY); return value ? fromB64(value) : null; }
  function credentials(password) { return new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password)); }

  async function createNewKdbx(password) {
    if (!window.kdbxweb) throw new Error('KDBX library did not load. Check your connection.');
    var db = kdbxweb.Kdbx.create(credentials(password), 'WiFi-Vault');
    var aes = kdbxweb.Consts && kdbxweb.Consts.KdfId && kdbxweb.Consts.KdfId.Aes;
    if (!aes) throw new Error('This kdbxweb version does not expose AES-KDF.');
    if (db.header && typeof db.header.setKdf === 'function') db.header.setKdf(aes);
    else if (db.header && db.header.kdfParameters) db.header.kdfParameters.set('$kdf', aes);
    activeDb = db; await persistActiveDb(); return db;
  }
  async function unlockKdbx(buffer, password) {
    if (!window.kdbxweb) throw new Error('KDBX library did not load.');
    activeDb = await kdbxweb.Kdbx.load(buffer, credentials(password));
    return activeDb;
  }
  function records() {
    if (!activeDb) return [];
    var group = activeDb.getDefaultGroup(), entries = group ? group.allEntries() : [];
    return entries.map(function (entry) {
      var lat = text(entry.fields.get('Latitude')), lng = text(entry.fields.get('Longitude'));
      return { id:idFor(entry), ssid:text(entry.fields.get('Title')), password:text(entry.fields.get('Password')), type:text(entry.fields.get('SecurityType')) || 'WPA2', location:{ name:text(entry.fields.get('LocationName')), latitude:lat ? Number(lat) : null, longitude:lng ? Number(lng) : null }, isFavorite:text(entry.fields.get('IsFavorite')) === 'true', updatedAt:entry.times && entry.times.lastModTime ? entry.times.lastModTime.getTime() : Date.now() };
    });
  }
  async function saveRecord(record) {
    if (!activeDb) throw new Error('Vault is locked.');
    var group = activeDb.getDefaultGroup(), entry = group.allEntries().find(function (e) { return idFor(e) === record.id; });
    if (!entry) entry = activeDb.createEntry(group);
    entry.fields.set('Title', record.ssid || ''); entry.fields.set('UserName', record.ssid || '');
    entry.fields.set('Password', kdbxweb.ProtectedValue.fromString(record.password || ''));
    entry.fields.set('SecurityType', record.type || 'WPA2'); entry.fields.set('IsFavorite', record.isFavorite ? 'true' : 'false');
    entry.fields.set('LocationName', record.location && record.location.name || '');
    entry.fields.set('Latitude', record.location && record.location.latitude !== null && record.location.latitude !== undefined ? String(record.location.latitude) : '');
    entry.fields.set('Longitude', record.location && record.location.longitude !== null && record.location.longitude !== undefined ? String(record.location.longitude) : '');
    await persistActiveDb();
  }
  async function deleteRecord(recordId) { var group = activeDb.getDefaultGroup(), entry = group.allEntries().find(function (e) { return idFor(e) === recordId; }); if (entry) { activeDb.remove(entry); await persistActiveDb(); } }
  function lock() { activeDb = null; vaultData = []; }
  async function exportKdbx() { if (!activeDb) throw new Error('Vault is locked.'); var url = URL.createObjectURL(new Blob([await activeDb.save()], {type:'application/x-keepass2'})), a = document.createElement('a'); a.href=url; a.download='wifi-vault-' + new Date().toISOString().slice(0,10) + '.kdbx'; a.click(); setTimeout(function(){URL.revokeObjectURL(url);},1000); }

  function cleanOwner(value) { return text(value).trim().replace(/^https?:\/\/github\.com\//i,'').replace(/^github\.com\//i,'').replace(/^\/|\/$/g,'').split('/')[0]; }
  function cleanRepo(value) { return text(value).trim().replace(/^https?:\/\/github\.com\//i,'').replace(/^github\.com\//i,'').replace(/^\/|\/$/g,'').split('/')[0]; }
  function cleanPath(value) { return (text(value).trim() || 'vault.kdbx').replace(/^https?:\/\/github\.com\//i,'').replace(/^\/+/, '').split('?')[0].split('#')[0].split('/').filter(Boolean).map(encodeURIComponent).join('/'); }
  function cleanToken(value) { return text(value).trim().replace(/^Bearer\s+/i,'').replace(/^token\s+/i,''); }
  function getConfig() { try { var c=JSON.parse(localStorage.getItem(GITHUB_CONFIG_KEY)||'null'); if (!c) return null; return {token:cleanToken(c.token),owner:cleanOwner(c.owner),repo:cleanRepo(c.repo),filePath:cleanPath(c.filePath)}; } catch (_) { return null; } }
  function saveConfig(token, owner, repo, filePath) { localStorage.setItem(GITHUB_CONFIG_KEY, JSON.stringify({token:cleanToken(token),owner:cleanOwner(owner),repo:cleanRepo(repo),filePath:cleanPath(filePath)})); }
  function apiHeaders(token) { return {'Authorization':(token.indexOf('ghp_')===0 ? 'token ' : 'Bearer ') + token,'Accept':'application/vnd.github+json','Content-Type':'application/json'}; }
  function apiUrl(c) { return 'https://api.github.com/repos/' + encodeURIComponent(c.owner) + '/' + encodeURIComponent(c.repo) + '/contents/' + c.filePath; }
  async function responseError(response, operation) { var body=await response.json().catch(function(){return {};}); var detail=body.message || body.error || response.statusText || 'Unknown error'; throw new Error((operation || 'GitHub request') + ' failed (HTTP ' + response.status + '): ' + detail); }
  async function githubRequest(url, options, operation) { var response; try { response=await fetch(url, options); } catch (e) { throw new Error((operation || 'GitHub request') + ' could not reach GitHub: ' + errorMessage(e)); } if (!response.ok) await responseError(response, operation); return response; }

  async function pullFromGitHub() {
    var c=getConfig(); if (!c || !c.token || !c.owner || !c.repo) throw new Error('GitHub sync is not configured.');
    var response; try { response=await fetch(apiUrl(c),{headers:apiHeaders(c.token)}); } catch(e) { throw new Error('GitHub download could not reach GitHub: '+errorMessage(e)); }
    if (response.status===404) { sessionStorage.removeItem(SHA_KEY); return {buffer:null,sha:null}; }
    if (!response.ok) await responseError(response,'GitHub download');
    var data=await response.json(); if (!data.content) throw new Error('GitHub returned an empty file response.');
    sessionStorage.setItem(SHA_KEY,data.sha); return {buffer:fromB64(data.content),sha:data.sha};
  }
  async function pushToGitHub() {
    var c=getConfig(); if (!c || !c.token || !c.owner || !c.repo) throw new Error('GitHub sync is not configured.');
    if (!activeDb) throw new Error('Unlock vault before syncing changes.');
    var url=apiUrl(c), content=b64(await activeDb.save()), sha=sessionStorage.getItem(SHA_KEY);
    async function getSha() { var r=await fetch(url,{headers:apiHeaders(c.token)}); if (r.ok) return (await r.json()).sha; if (r.status===404) return null; await responseError(r,'GitHub metadata lookup'); }
    sha=await getSha();
    async function put(currentSha) { var payload={message:'Sync Wi-Fi Vault: '+new Date().toISOString(),content:content}; if(currentSha) payload.sha=currentSha; return githubRequest(url,{method:'PUT',headers:apiHeaders(c.token),body:JSON.stringify(payload)},'GitHub upload'); }
    var result; try { result=await put(sha); } catch(e) { if (!/HTTP 409/.test(errorMessage(e))) throw e; result=await put(await getSha()); }
    var data=await result.json(); var newSha=data.content && data.content.sha; if(newSha) sessionStorage.setItem(SHA_KEY,newSha); return data;
  }

  function parseWifiQR(raw) {
    var str=text(raw).trim(), ssid='', password='', type='WPA2', match;
    if (!str) return null;
    match=str.match(/<SSID\s*>([\s\S]*?)<\/SSID\s*>/i); var pm=str.match(/<PWD\s*>([\s\S]*?)<\/PWD\s*>/i); if(match||pm) return {ssid:match?match[1].trim():'',password:pm?pm[1].trim():'',type:'WPA2'};
    if (/^WIFI:/i.test(str)) { var fields={}, body=str.replace(/^WIFI:/i,''); var key='', value=''; for(var i=0;i<body.length;i++){var ch=body[i]; if(ch==='\\'&&i+1<body.length){value+=body[++i];continue;} if(ch===':'){key=value;value='';continue;} if(ch===';' ){if(key) fields[key]=value;key='';value='';continue;} value+=ch;} if(key) fields[key]=value; ssid=fields.S||''; password=fields.P||''; type=fields.T||'WPA2'; return {ssid:ssid,password:password,type:type}; }
    var sm=str.match(/(?:SSID|Network(?:\s+Name)?)[\s:=]+([^\r\n;]+)/i), pw=str.match(/(?:PWD|Password|Key|Passphrase)[\s:=]+([^\r\n;]+)/i); if(sm||pw) return {ssid:sm?sm[1].trim():'',password:pw?pw[1].trim():'',type:'WPA2'}; return null;
  }
  async function startCamera(video) { if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia) throw new Error('Camera access is not supported.'); videoStream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1280},height:{ideal:720}},audio:false}); video.srcObject=videoStream; await video.play(); }
  function stopCamera(){if(videoStream){videoStream.getTracks().forEach(function(t){t.stop();});videoStream=null;}if(qrScanInterval){clearInterval(qrScanInterval);qrScanInterval=null;}}
  function monitorQR(video,canvas,done){var ctx=canvas.getContext('2d'), busy=false; qrScanInterval=setInterval(async function(){if(busy||video.readyState<2)return;busy=true;try{var value=null;if('BarcodeDetector' in window){var found=await new BarcodeDetector({formats:['qr_code']}).detect(video);if(found[0])value=found[0].rawValue;}else{canvas.width=video.videoWidth;canvas.height=video.videoHeight;ctx.drawImage(video,0,0,canvas.width,canvas.height);var code=window.jsQR&&jsQR(ctx.getImageData(0,0,canvas.width,canvas.height).data,canvas.width,canvas.height);if(code)value=code.data;}var parsed=parseWifiQR(value);if(parsed&&parsed.ssid){stopCamera();done(parsed);}}catch(_){}finally{busy=false;}},400);}
  async function ocr(video,canvas){if(!window.Tesseract)throw new Error('OCR library did not load.');canvas.width=video.videoWidth;canvas.height=video.videoHeight;var ctx=canvas.getContext('2d');ctx.drawImage(video,0,0,canvas.width,canvas.height);var result=await Tesseract.recognize(canvas,'eng');return parseWifiQR(result.data.text)||parseOcrText(result.data.text);}
  function parseOcrText(value){var s=text(value), sm=s.match(/(?:SSID|Network\s*Name|Wi[- ]Fi\s*Name)\s*[:=]\s*([^\r\n]+)/i), pm=s.match(/(?:Password|PWD|PIN|Key|Passphrase|Network\s*Key)\s*[:=]\s*([^\r\n]+)/i);return sm||pm?{ssid:sm?sm[1].trim():'',password:pm?pm[1].trim():'',type:'WPA2'}:null;}

  function updateStatus(){var el=document.getElementById('vault-status-indicator');if(el){el.textContent=activeDb?'Unlocked':'Locked';el.className='status-badge '+(activeDb?'unlocked':'locked');}}
  function showAuth(){setHidden(document.getElementById('auth-modal'),false);var input=document.getElementById('master-password-input');if(input){input.value='';setTimeout(function(){input.focus();},0);}updateStatus();}
  function locationFields(data){var n=document.getElementById('input-location-name'), box=document.getElementById('location-coordinates-display');if(n)n.value=data&&data.name||'';activeCoordinates=data&&data.latitude!==null&&data.latitude!==undefined&&data.longitude!==null?{latitude:data.latitude,longitude:data.longitude}:null;if(activeCoordinates){document.getElementById('display-lat').textContent=activeCoordinates.latitude.toFixed(5);document.getElementById('display-lng').textContent=activeCoordinates.longitude.toFixed(5);}setHidden(box,!activeCoordinates);}
  function openForm(data){editTargetId=data&&data.id||null;document.getElementById('input-ssid').value=data&&data.ssid||'';document.getElementById('input-password').value=data&&data.password||'';document.getElementById('input-auth-type').value=data&&data.type||'WPA2';locationFields(data&&data.location);setHidden(document.getElementById('confirm-modal'),false);}
  function render(){var list=document.getElementById('wifi-list'), empty=document.getElementById('vault-empty'), q=(document.getElementById('vault-search').value||'').toLowerCase();list.innerHTML='';var filtered=vaultData.filter(function(r){return(activeFilter==='all'||r.isFavorite)&&((r.ssid||'').toLowerCase().indexOf(q)>=0||(r.location&&r.location.name||'').toLowerCase().indexOf(q)>=0);});setHidden(empty,filtered.length!==0);filtered.forEach(function(r){var card=document.createElement('div');card.className='wifi-card';card.innerHTML='<div class="card-top"><div><div class="card-ssid">'+esc(r.ssid)+'</div><div class="card-meta">'+esc(r.type)+' • Updated '+new Date(r.updatedAt).toLocaleDateString()+'</div></div><button type="button" class="btn-fav '+(r.isFavorite?'active':'')+'">★</button></div><div class="password-display"><span class="pass-text masked-pass">••••••••</span><button type="button" class="btn-card btn-toggle-pass">Show</button></div><div class="card-actions"><button type="button" class="btn-card btn-copy">Copy</button><button type="button" class="btn-card btn-edit">Edit</button><button type="button" class="btn-card danger btn-delete">Delete</button></div>';
      card.querySelector('.btn-toggle-pass').onclick=function(){var p=card.querySelector('.pass-text'),show=p.dataset.revealed==='true';p.textContent=show?'••••••••':r.password;p.dataset.revealed=String(!show);this.textContent=show?'Show':'Hide';};
      card.querySelector('.btn-copy').onclick=async function(){try{await navigator.clipboard.writeText(r.password);alert('Password copied.');}catch(_){alert('Clipboard access failed.');}};
      card.querySelector('.btn-fav').onclick=async function(){r.isFavorite=!r.isFavorite;await saveRecord(r);vaultData=records();render();};card.querySelector('.btn-edit').onclick=function(){openForm(r);};card.querySelector('.btn-delete').onclick=async function(){if(confirm('Delete "'+r.ssid+'"?')){await deleteRecord(r.id);vaultData=records();render();}};list.appendChild(card);});}
  function refresh(){if(activeDb){vaultData=records();render();}updateStatus();}

  window.handleUnlockVault=async function(event){if(event)event.preventDefault();var input=document.getElementById('master-password-input'), password=input&&input.value||'';if(!password)return alert('Please enter your master password.');var btn=document.getElementById('btn-unlock-vault');try{btn.disabled=true;var buffer=storedBuffer();if(!buffer)return alert('No vault found. Create a vault or sync one first.');await unlockKdbx(buffer,password);setHidden(document.getElementById('auth-modal'),true);refresh();}catch(e){alert('Failed to unlock: '+errorMessage(e));}finally{btn.disabled=false;}};
  window.handleCreateVault=async function(event){if(event)event.preventDefault();var input=document.getElementById('master-password-input'),password=input&&input.value||'';if(password.length<6)return alert('Master password must be at least 6 characters.');var btn=document.getElementById('btn-create-new-kdbx');try{btn.disabled=true;await createNewKdbx(password);setHidden(document.getElementById('auth-modal'),true);refresh();}catch(e){alert('Error creating vault: '+errorMessage(e));}finally{btn.disabled=false;}};

  document.addEventListener('DOMContentLoaded',function(){
    var $=function(id){return document.getElementById(id);};
    $('vault-search').oninput=render;$('filter-all').onclick=function(){activeFilter='all';$('filter-all').classList.add('active');$('filter-favorites').classList.remove('active');render();};$('filter-favorites').onclick=function(){activeFilter='favorites';$('filter-favorites').classList.add('active');$('filter-all').classList.remove('active');render();};
    $('btn-lock-vault').onclick=function(){lock();$('wifi-list').innerHTML='';showAuth();};$('btn-export-kdbx').onclick=async function(){try{await exportKdbx();}catch(e){alert(errorMessage(e));}};$('btn-manual-add').onclick=function(){if(!activeDb)return showAuth();openForm(null);};
    $('btn-open-scanner').onclick=async function(){if(!activeDb)return showAuth();setHidden($('scanner-modal'),false);try{await startCamera($('camera-stream'));monitorQR($('camera-stream'),$('capture-canvas'),function(data){setHidden($('scanner-modal'),true);openForm(data);});}catch(e){$('scan-status').textContent=errorMessage(e);}};$('btn-close-scanner').onclick=function(){stopCamera();setHidden($('scanner-modal'),true);};$('btn-run-ocr').onclick=async function(){var b=$('btn-run-ocr');try{b.disabled=true;$('scan-status').textContent='Analyzing...';var data=await ocr($('camera-stream'),$('capture-canvas'));if(!data||!data.ssid)throw new Error('No Wi-Fi details detected.');stopCamera();setHidden($('scanner-modal'),true);openForm(data);}catch(e){$('scan-status').textContent=errorMessage(e);}finally{b.disabled=false;}};
    $('btn-detect-location').onclick=async function(){try{var p=await new Promise(function(resolve,reject){navigator.geolocation.getCurrentPosition(function(x){resolve(x.coords);},function(x){reject(new Error(x.message));},{enableHighAccuracy:true,timeout:8000});});activeCoordinates={latitude:p.latitude,longitude:p.longitude};locationFields({name:$('input-location-name').value,latitude:p.latitude,longitude:p.longitude});}catch(e){alert(errorMessage(e));}};$('btn-clear-coords').onclick=function(){activeCoordinates=null;setHidden($('location-coordinates-display'),true);};
    $('btn-cancel-save').onclick=function(){setHidden($('confirm-modal'),true);editTargetId=null;};$('btn-confirm-save').onclick=async function(){var ssid=$('input-ssid').value.trim();if(!ssid)return alert('Network SSID is required.');var old=vaultData.find(function(x){return x.id===editTargetId;}), r={id:editTargetId||((crypto.randomUUID&&crypto.randomUUID())||String(Date.now())),ssid:ssid,password:$('input-password').value,type:$('input-auth-type').value,isFavorite:old?old.isFavorite:false,location:{name:$('input-location-name').value.trim(),latitude:activeCoordinates?activeCoordinates.latitude:null,longitude:activeCoordinates?activeCoordinates.longitude:null}};try{await saveRecord(r);setHidden($('confirm-modal'),true);refresh();}catch(e){alert('Failed to save: '+errorMessage(e));}};
    $('file-import-kdbx').onchange=function(e){var file=e.target.files&&e.target.files[0],password=$('master-password-input').value;if(!file||!password)return alert('Select a file and enter its master password.');var reader=new FileReader();reader.onload=async function(){try{await unlockKdbx(reader.result,password);await persistActiveDb();setHidden($('auth-modal'),true);refresh();}catch(x){alert('Failed to decrypt imported file: '+errorMessage(x));}};reader.readAsArrayBuffer(file);};
    $('btn-open-settings').onclick=function(){var c=getConfig();if(c){$('gh-token').value=c.token;$('gh-owner').value=c.owner;$('gh-repo').value=c.repo;$('gh-filename').value=c.filePath;}setHidden($('settings-modal'),false);};$('btn-close-settings').onclick=function(){setHidden($('settings-modal'),true);};$('btn-save-settings').onclick=function(){if(!$('gh-token').value.trim()||!$('gh-owner').value.trim()||!$('gh-repo').value.trim())return alert('Token, owner, and repository are required.');saveConfig($('gh-token').value,$('gh-owner').value,$('gh-repo').value,$('gh-filename').value);setHidden($('settings-modal'),true);alert('GitHub sync configuration saved.');};
    $('btn-sync-cloud').onclick=async function(){var b=$('btn-sync-cloud');try{b.disabled=true;b.textContent='⏳ Syncing...';if(activeDb){await pushToGitHub();alert('Encrypted vault uploaded successfully.');}else{var pulled=await pullFromGitHub();if(!pulled.buffer)alert('No remote vault found. Create and unlock a vault first.');else{localStorage.setItem(STORAGE_KEY,b64(pulled.buffer));alert('Remote vault downloaded. Enter its master password to unlock.');}showAuth();}}catch(e){alert('Sync Failed: '+errorMessage(e));}finally{b.disabled=false;b.textContent='🔄 Sync';}};
    showAuth();
  });
})();
