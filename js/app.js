// --- Global State & Database Engine ---
let activeDb = null;
const STORAGE_KEY = 'kdbx_binary_store';

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

async function persistActiveDb() {
  if (!activeDb) return;
  const binary = await activeDb.save();
  localStorage.setItem(STORAGE_KEY, arrayBufferToBase64(binary));
}

function getStoredKdbxBuffer() {
  const b64 = localStorage.getItem(STORAGE_KEY);
  return b64 ? base64ToArrayBuffer(b64) : null;
}

async function createNewKdbx(masterPassword) {
  if (typeof kdbxweb === 'undefined') {
    throw new Error('KDBX library not loaded. Check internet connection.');
  }

  const credentials = new kdbxweb.Credentials(
    kdbxweb.ProtectedValue.fromString(masterPassword)
  );

  // Create database
  const db = kdbxweb.Kdbx.create(credentials, 'WiFi-Vault');

  // Explicitly set Key Derivation to AES-KDF so it uses native WebCrypto instead of missing Argon2 WASM
  if (kdbxweb.Consts && kdbxweb.Consts.KdfId) {
    db.header.setKdf(kdbxweb.Consts.KdfId.Aes);
  }

  activeDb = db;
  await persistActiveDb();
  return db;
}


async function unlockKdbx(arrayBuffer, masterPassword) {
  if (typeof kdbxweb === 'undefined') {
    throw new Error('KDBX library not loaded.');
  }
  const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(masterPassword));
  const db = await kdbxweb.Kdbx.load(arrayBuffer, credentials);
  activeDb = db;
  return db;
}

function getKdbxRecords() {
  if (!activeDb) return [];
  const defaultGroup = activeDb.getDefaultGroup();
  const entries = defaultGroup ? defaultGroup.allEntries() : [];

  return entries.map(entry => {
    const passwordField = entry.fields.get('Password');
    let passValue = '';
    if (passwordField) {
      passValue = typeof passwordField.getText === 'function' ? passwordField.getText() : passwordField.toString();
    }
    const locLat = entry.fields.get('Latitude');
    const locLng = entry.fields.get('Longitude');

    return {
      id: entry.uuid.id || entry.uuid.toString(),
      ssid: entry.fields.get('Title') || '',
      password: passValue,
      type: entry.fields.get('SecurityType') || 'WPA2',
      location: {
        name: entry.fields.get('LocationName') || '',
        latitude: locLat ? parseFloat(locLat) : null,
        longitude: locLng ? parseFloat(locLng) : null
      },
      isFavorite: entry.fields.get('IsFavorite') === 'true',
      updatedAt: entry.times?.lastModTime ? entry.times.lastModTime.getTime() : Date.now()
    };
  });
}

async function saveKdbxRecord(record) {
  if (!activeDb) throw new Error('Database is locked.');
  const group = activeDb.getDefaultGroup();
  let entry = group.allEntries().find(e => (e.uuid.id || e.uuid.toString()) === record.id);
  if (!entry) {
    entry = activeDb.createEntry(group);
  }

  entry.fields.set('Title', record.ssid);
  entry.fields.set('UserName', record.ssid);
  entry.fields.set('Password', kdbxweb.ProtectedValue.fromString(record.password));
  entry.fields.set('SecurityType', record.type || 'WPA2');
  entry.fields.set('IsFavorite', record.isFavorite ? 'true' : 'false');
  entry.fields.set('LocationName', record.location?.name || '');
  entry.fields.set('Latitude', record.location?.latitude ? record.location.latitude.toString() : '');
  entry.fields.set('Longitude', record.location?.longitude ? record.location.longitude.toString() : '');

  await persistActiveDb();
  return entry;
}

async function deleteKdbxRecord(recordId) {
  if (!activeDb) throw new Error('Database is locked.');
  const group = activeDb.getDefaultGroup();
  const entry = group.allEntries().find(e => (e.uuid.id || e.uuid.toString()) === recordId);
  if (entry) {
    activeDb.remove(entry);
    await persistActiveDb();
  }
}

async function exportKdbxFile() {
  if (!activeDb) throw new Error('Vault is locked.');
  const binary = await activeDb.save();
  const blob = new Blob([binary], { type: 'application/x-keepass2' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `wifi-vault-${new Date().toISOString().slice(0, 10)}.kdbx`;
  a.click();
  URL.revokeObjectURL(url);
}

function isVaultUnlocked() {
  return activeDb !== null;
}

function lockVault() {
  activeDb = null;
}

// --- Scanner Subsystem ---
let videoStream = null;
let qrScanInterval = null;

async function startCamera(videoElement) {
  videoStream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
    audio: false
  });
  videoElement.srcObject = videoStream;
  await videoElement.play();
}

function stopCamera() {
  if (videoStream) {
    videoStream.getTracks().forEach(t => t.stop());
    videoStream = null;
  }
  if (qrScanInterval) {
    clearInterval(qrScanInterval);
    qrScanInterval = null;
  }
}

function parseWifiQR(rawString) {
  if (!rawString) return null;
  const str = rawString.trim();

  // 1. Jio / Arcadyan / ISP XML-based QR Format
  if (str.includes('<SSID>') || str.includes('<PWD>')) {
    const ssidMatch = str.match(/<SSID>(.*?)<\/SSID>/i);
    const pwdMatch = str.match(/<PWD>(.*?)<\/PWD>/i);

    return {
      ssid: ssidMatch ? ssidMatch[1].trim() : '',
      password: pwdMatch ? pwdMatch[1].trim() : '',
      type: 'WPA2'
    };
  }

  // 2. Standard Android / iOS QR Format (WIFI:T:WPA;S:MyNet;P:Pass;;)
  if (str.startsWith('WIFI:')) {
    const ssidMatch = str.match(/S:((?:\\;|[^;])+);/);
    const passMatch = str.match(/P:((?:\\;|[^;])+);/);
    const typeMatch = str.match(/T:([^;]+);/);

    return {
      ssid: ssidMatch ? ssidMatch[1].replace(/\\;/g, ';') : '',
      password: passMatch ? passMatch[1].replace(/\\;/g, ';') : '',
      type: typeMatch ? typeMatch[1] : 'WPA2'
    };
  }

  // 3. Fallback: Check if string has plain key-value or tags
  const fallbackSsid = str.match(/(?:SSID|Network)[\s:=]+([^\r\n]+)/i);
  const fallbackPwd = str.match(/(?:PWD|Password|Key)[\s:=]+([^\r\n]+)/i);
  if (fallbackSsid || fallbackPwd) {
    return {
      ssid: fallbackSsid ? fallbackSsid[1].trim() : '',
      password: fallbackPwd ? fallbackPwd[1].trim() : '',
      type: 'WPA2'
    };
  }

  return null;
}


function monitorQRCode(videoElement, canvasElement, onDetected) {
  const ctx = canvasElement.getContext('2d');
  if ('BarcodeDetector' in window) {
    const detector = new BarcodeDetector({ formats: ['qr_code'] });
    qrScanInterval = setInterval(async () => {
      try {
        const barcodes = await detector.detect(videoElement);
        if (barcodes.length > 0) {
          const parsed = parseWifiQR(barcodes[0].rawValue);
          if (parsed) {
            stopCamera();
            onDetected(parsed);
          }
        }
      } catch (_) {}
    }, 400);
  } else {
    qrScanInterval = setInterval(() => {
      if (videoElement.readyState === videoElement.HAVE_ENOUGH_DATA) {
        canvasElement.width = videoElement.videoWidth;
        canvasElement.height = videoElement.videoHeight;
        ctx.drawImage(videoElement, 0, 0, canvasElement.width, canvasElement.height);
        const imgData = ctx.getImageData(0, 0, canvasElement.width, canvasElement.height);
        const code = window.jsQR ? window.jsQR(imgData.data, imgData.width, imgData.height) : null;
        if (code && code.data) {
          const parsed = parseWifiQR(code.data);
          if (parsed) {
            stopCamera();
            onDetected(parsed);
          }
        }
      }
    }, 400);
  }
}

function scanRouterText(videoElement, canvasElement) {
  if (typeof Tesseract === 'undefined') {
    throw new Error('OCR library (Tesseract) not loaded.');
  }
  canvasElement.width = videoElement.videoWidth;
  canvasElement.height = videoElement.videoHeight;
  const ctx = canvasElement.getContext('2d');
  ctx.drawImage(videoElement, 0, 0, canvasElement.width, canvasElement.height);

  const imgData = ctx.getImageData(0, 0, canvasElement.width, canvasElement.height);
  const d = imgData.data;
  for (let i = 0; i < d.length; i += 4) {
    const avg = 0.3 * d[i] + 0.59 * d[i + 1] + 0.11 * d[i + 2];
    const threshold = avg > 120 ? 255 : 0;
    d[i] = threshold;
    d[i + 1] = threshold;
    d[i + 2] = threshold;
  }
  ctx.putImageData(imgData, 0, 0);

  return Tesseract.recognize(canvasElement, 'eng').then(({ data: { text } }) => {
    // Check XML format first
    if (text.includes('<SSID>') || text.includes('<PWD>')) {
      const ssidMatch = text.match(/<SSID>(.*?)<\/SSID>/i);
      const pwdMatch = text.match(/<PWD>(.*?)<\/PWD>/i);
      return {
        ssid: ssidMatch ? ssidMatch[1].trim() : '',
        password: pwdMatch ? pwdMatch[1].trim() : '',
        type: 'WPA2'
      };
    }

    const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
    const res = { ssid: '', password: '', type: 'WPA2' };
    const ssidPat = /(?:SSID|Network\s*Name|Wi-Fi\s*Name|Wireless\s*Name)[\s:]+([A-Za-z0-9_\-\.]+)/i;
    const passPat = /(?:Password|PWD|PIN|Key|WPA\s*Key|WPA2\s*Key|Network\s*Key|Passphrase)[\s:]+([A-Za-z0-9!@#$%^&*_\-\.]+)/i;

    for (const line of lines) {
      if (!res.ssid) {
        const m = line.match(ssidPat);
        if (m) res.ssid = m[1];
      }
      if (!res.password) {
        const m = line.match(passPat);
        if (m) res.password = m[1];
      }
    }
    return res;
  });
}


// --- Geolocation Subsystem ---
function getCurrentCoordinates() {
  return new Promise((resolve, reject) => {
    if (!('geolocation' in navigator)) {
      return reject(new Error('Geolocation is not supported by your browser.'));
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ latitude: pos.coords.latitude, longitude: pos.coords.longitude }),
      (err) => reject(new Error(err.message)),
      { enableHighAccuracy: true, timeout: 8000 }
    );
  });
}

async function reverseGeocode(lat, lng) {
  try {
    const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lng}`);
    if (!res.ok) return '';
    const data = await res.json();
    return data.address?.suburb || data.address?.neighbourhood || data.address?.city || '';
  } catch (_) {
    return '';
  }
}

// --- UI Application Logic ---
let vaultData = [];
let activeFilter = 'all';
let editTargetId = null;
let activeCoordinates = null;

function escapeHTML(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, t => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[t] || t));
}

function updateVaultUI() {
  const statusBadge = document.getElementById('vault-status-indicator');
  const unlocked = isVaultUnlocked();
  if (statusBadge) {
    statusBadge.textContent = unlocked ? 'Unlocked' : 'Locked';
    statusBadge.className = `status-badge ${unlocked ? 'unlocked' : 'locked'}`;
  }
}

function showAuthPrompt() {
  const authModal = document.getElementById('auth-modal');
  const masterPasswordInput = document.getElementById('master-password-input');
  const authError = document.getElementById('auth-error');

  if (authModal) authModal.classList.remove('hidden');
  if (masterPasswordInput) masterPasswordInput.value = '';
  if (authError) {
    authError.textContent = '';
    authError.classList.add('hidden');
  }
  updateVaultUI();
}

function renderCards() {
  const wifiList = document.getElementById('wifi-list');
  const vaultEmpty = document.getElementById('vault-empty');
  const searchInput = document.getElementById('vault-search');
  const query = searchInput ? searchInput.value.trim().toLowerCase() : '';

  const filtered = vaultData.filter(item => {
    const matchesSsid = item.ssid?.toLowerCase().includes(query);
    const matchesLoc = item.location?.name?.toLowerCase().includes(query);
    const matchesFilter = activeFilter === 'favorites' ? item.isFavorite : true;
    return (matchesSsid || matchesLoc) && matchesFilter;
  });

  if (wifiList) wifiList.innerHTML = '';
  if (vaultEmpty) vaultEmpty.classList.toggle('hidden', filtered.length > 0);

  filtered.forEach(record => {
    const card = document.createElement('div');
    card.className = 'wifi-card';
    const locText = record.location?.name || (record.location?.latitude ? `${record.location.latitude.toFixed(3)}, ${record.location.longitude.toFixed(3)}` : '');
    const locBadge = locText ? `<div class="card-location-badge">📍 ${escapeHTML(locText)}</div>` : '';
    const dateStr = new Date(record.updatedAt).toLocaleDateString();

    card.innerHTML = `
      <div class="card-top">
        <div>
          <div class="card-ssid">${escapeHTML(record.ssid)}</div>
          <div class="card-meta">${escapeHTML(record.type || 'WPA2')} • Updated ${dateStr}</div>
          ${locBadge}
        </div>
        <button type="button" class="btn-fav ${record.isFavorite ? 'active' : ''}">★</button>
      </div>
      <div class="password-display">
        <span class="pass-text masked-pass" data-revealed="false">••••••••</span>
        <button type="button" class="btn-card btn-toggle-pass">Show</button>
      </div>
      <div class="card-actions">
        <button type="button" class="btn-card btn-copy">Copy</button>
        <button type="button" class="btn-card btn-edit">Edit</button>
        <button type="button" class="btn-card danger btn-delete">Delete</button>
      </div>
    `;

    const toggleBtn = card.querySelector('.btn-toggle-pass');
    const passText = card.querySelector('.pass-text');
    toggleBtn.addEventListener('click', () => {
      const isRev = passText.dataset.revealed === 'true';
      passText.textContent = isRev ? '••••••••' : record.password;
      passText.classList.toggle('masked-pass', isRev);
      passText.dataset.revealed = (!isRev).toString();
      toggleBtn.textContent = isRev ? 'Show' : 'Hide';
    });

    card.querySelector('.btn-copy').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(record.password);
        alert(`Copied password for "${record.ssid}"`);
      } catch (_) {
        alert('Failed to copy.');
      }
    });

    card.querySelector('.btn-fav').addEventListener('click', async () => {
      record.isFavorite = !record.isFavorite;
      await saveKdbxRecord(record);
      await refreshVault();
    });

    card.querySelector('.btn-edit').addEventListener('click', () => {
      editTargetId = record.id;
      document.getElementById('input-ssid').value = record.ssid;
      document.getElementById('input-password').value = record.password;
      document.getElementById('input-auth-type').value = record.type || 'WPA2';
      resetLocationFields(record.location);
      document.getElementById('confirm-modal').classList.remove('hidden');
    });

    card.querySelector('.btn-delete').addEventListener('click', async () => {
      if (confirm(`Delete "${record.ssid}"?`)) {
        await deleteKdbxRecord(record.id);
        await refreshVault();
      }
    });

    if (wifiList) wifiList.appendChild(card);
  });
}

async function refreshVault() {
  if (!isVaultUnlocked()) return;
  vaultData = getKdbxRecords();
  renderCards();
}

function resetLocationFields(data = null) {
  const inputLocationName = document.getElementById('input-location-name');
  const displayLat = document.getElementById('display-lat');
  const displayLng = document.getElementById('display-lng');
  const coordsDisplay = document.getElementById('location-coordinates-display');

  if (data) {
    if (inputLocationName) inputLocationName.value = data.name || '';
    if (data.latitude && data.longitude) {
      activeCoordinates = { latitude: data.latitude, longitude: data.longitude };
      if (displayLat) displayLat.textContent = data.latitude.toFixed(5);
      if (displayLng) displayLng.textContent = data.longitude.toFixed(5);
      if (coordsDisplay) coordsDisplay.classList.remove('hidden');
    } else {
      activeCoordinates = null;
      if (coordsDisplay) coordsDisplay.classList.add('hidden');
    }
  } else {
    if (inputLocationName) inputLocationName.value = '';
    activeCoordinates = null;
    if (coordsDisplay) coordsDisplay.classList.add('hidden');
  }
}

function openConfirmationForm(data = {}) {
  editTargetId = null;
  document.getElementById('input-ssid').value = data.ssid || '';
  document.getElementById('input-password').value = data.password || '';
  document.getElementById('input-auth-type').value = data.type || 'WPA2';
  resetLocationFields();
  document.getElementById('confirm-modal').classList.remove('hidden');
}

// --- Top-Level Global Button Actions ---
window.handleUnlockVault = async function () {
  const masterPasswordInput = document.getElementById('master-password-input');
  const password = masterPasswordInput ? masterPasswordInput.value.trim() : '';
  if (!password) {
    alert('Please enter a master password.');
    return;
  }
  try {
    const buffer = getStoredKdbxBuffer();
    if (!buffer) {
      alert('No vault found yet. Click "Create New Vault" instead.');
      return;
    }
    await unlockKdbx(buffer, password);
    document.getElementById('auth-modal').classList.add('hidden');
    updateVaultUI();
    await refreshVault();
  } catch (err) {
    alert('Failed to unlock: Incorrect master password or corrupted file.');
  }
};

window.handleCreateVault = async function () {
  const masterPasswordInput = document.getElementById('master-password-input');
  const password = masterPasswordInput ? masterPasswordInput.value.trim() : '';
  if (!password || password.length < 6) {
    alert('Master password must be at least 6 characters.');
    return;
  }
  const btn = document.getElementById('btn-create-new-kdbx');
  try {
    if (btn) btn.textContent = 'Creating...';
    await createNewKdbx(password);
    document.getElementById('auth-modal').classList.add('hidden');
    updateVaultUI();
    await refreshVault();
  } catch (err) {
    alert('Error creating vault: ' + err.message);
  } finally {
    if (btn) btn.textContent = 'Create New Vault';
  }
};

// --- DOM Event Initialization ---
document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('vault-search');
  const filterAll = document.getElementById('filter-all');
  const filterFavs = document.getElementById('filter-favorites');
  const btnLockVault = document.getElementById('btn-lock-vault');
  const btnExportKdbx = document.getElementById('btn-export-kdbx');
  const btnManualAdd = document.getElementById('btn-manual-add');
  const btnOpenScanner = document.getElementById('btn-open-scanner');
  const btnCloseScanner = document.getElementById('btn-close-scanner');
  const btnRunOCR = document.getElementById('btn-run-ocr');
  const scannerModal = document.getElementById('scanner-modal');
  const scanStatus = document.getElementById('scan-status');
  const video = document.getElementById('camera-stream');
  const canvas = document.getElementById('capture-canvas');
  const btnDetectLocation = document.getElementById('btn-detect-location');
  const btnClearCoords = document.getElementById('btn-clear-coords');
  const btnConfirmSave = document.getElementById('btn-confirm-save');
  const btnCancelSave = document.getElementById('btn-cancel-save');
  const fileImportKdbx = document.getElementById('file-import-kdbx');

  if (searchInput) searchInput.addEventListener('input', renderCards);

  if (filterAll) {
    filterAll.addEventListener('click', () => {
      activeFilter = 'all';
      filterAll.classList.add('active');
      if (filterFavs) filterFavs.classList.remove('active');
      renderCards();
    });
  }

  if (filterFavs) {
    filterFavs.addEventListener('click', () => {
      activeFilter = 'favorites';
      filterFavs.classList.add('active');
      if (filterAll) filterAll.classList.remove('active');
      renderCards();
    });
  }

  if (btnLockVault) {
    btnLockVault.addEventListener('click', () => {
      lockVault();
      const wifiList = document.getElementById('wifi-list');
      if (wifiList) wifiList.innerHTML = '';
      showAuthPrompt();
    });
  }

  if (btnExportKdbx) {
    btnExportKdbx.addEventListener('click', async () => {
      try {
        await exportKdbxFile();
      } catch (err) {
        alert(err.message);
      }
    });
  }

  if (btnManualAdd) {
    btnManualAdd.addEventListener('click', () => {
      if (!isVaultUnlocked()) return showAuthPrompt();
      editTargetId = null;
      document.getElementById('input-ssid').value = '';
      document.getElementById('input-password').value = '';
      document.getElementById('input-auth-type').value = 'WPA2';
      resetLocationFields();
      document.getElementById('confirm-modal').classList.remove('hidden');
    });
  }

  if (btnOpenScanner) {
    btnOpenScanner.addEventListener('click', async () => {
      if (!isVaultUnlocked()) return showAuthPrompt();
      if (scannerModal) scannerModal.classList.remove('hidden');
      if (scanStatus) scanStatus.textContent = 'Point at QR code or router sticker...';
      try {
        await startCamera(video);
        monitorQRCode(video, canvas, (data) => {
          stopCamera();
          if (scannerModal) scannerModal.classList.add('hidden');
          openConfirmationForm(data);
        });
      } catch (err) {
        if (scanStatus) scanStatus.textContent = err.message;
      }
    });
  }

  if (btnCloseScanner) {
    btnCloseScanner.addEventListener('click', () => {
      stopCamera();
      if (scannerModal) scannerModal.classList.add('hidden');
    });
  }

  if (btnRunOCR) {
    btnRunOCR.addEventListener('click', async () => {
      if (scanStatus) scanStatus.textContent = 'Analyzing with OCR...';
      btnRunOCR.disabled = true;
      try {
        const data = await scanRouterText(video, canvas);
        stopCamera();
        if (scannerModal) scannerModal.classList.add('hidden');
        openConfirmationForm(data);
      } catch (err) {
        if (scanStatus) scanStatus.textContent = 'Could not detect credentials.';
      } finally {
        btnRunOCR.disabled = false;
      }
    });
  }

  if (btnDetectLocation) {
    btnDetectLocation.addEventListener('click', async () => {
      btnDetectLocation.disabled = true;
      btnDetectLocation.textContent = '⏳';
      try {
        const coords = await getCurrentCoordinates();
        activeCoordinates = coords;
        const displayLat = document.getElementById('display-lat');
        const displayLng = document.getElementById('display-lng');
        const coordsDisplay = document.getElementById('location-coordinates-display');
        const inputLocationName = document.getElementById('input-location-name');

        if (displayLat) displayLat.textContent = coords.latitude.toFixed(5);
        if (displayLng) displayLng.textContent = coords.longitude.toFixed(5);
        if (coordsDisplay) coordsDisplay.classList.remove('hidden');
        if (inputLocationName && !inputLocationName.value.trim()) {
          const place = await reverseGeocode(coords.latitude, coords.longitude);
          if (place) inputLocationName.value = place;
        }
      } catch (err) {
        alert(err.message);
      } finally {
        btnDetectLocation.disabled = false;
        btnDetectLocation.textContent = '🎯';
      }
    });
  }

  if (btnClearCoords) {
    btnClearCoords.addEventListener('click', () => {
      activeCoordinates = null;
      const coordsDisplay = document.getElementById('location-coordinates-display');
      if (coordsDisplay) coordsDisplay.classList.add('hidden');
    });
  }

  if (btnConfirmSave) {
    btnConfirmSave.addEventListener('click', async () => {
      const inputSsid = document.getElementById('input-ssid');
      const inputPassword = document.getElementById('input-password');
      const inputAuthType = document.getElementById('input-auth-type');
      const inputLocationName = document.getElementById('input-location-name');

      const ssidVal = inputSsid ? inputSsid.value.trim() : '';
      if (!ssidVal) return alert('Network SSID is required.');

      const payload = {
        id: editTargetId || (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2)),
        ssid: ssidVal,
        password: inputPassword ? inputPassword.value : '',
        type: inputAuthType ? inputAuthType.value : 'WPA2',
        location: {
          name: inputLocationName ? inputLocationName.value.trim() : '',
          latitude: activeCoordinates ? activeCoordinates.latitude : null,
          longitude: activeCoordinates ? activeCoordinates.longitude : null
        },
        isFavorite: false,
        updatedAt: Date.now()
      };

      if (editTargetId) {
        const existing = vaultData.find(item => item.id === editTargetId);
        if (existing) payload.isFavorite = existing.isFavorite;
      }

      try {
        await saveKdbxRecord(payload);
        editTargetId = null;
        document.getElementById('confirm-modal').classList.add('hidden');
        resetLocationFields();
        await refreshVault();
      } catch (err) {
        alert('Failed to save to encrypted vault: ' + err.message);
      }
    });
  }

  if (btnCancelSave) {
    btnCancelSave.addEventListener('click', () => {
      editTargetId = null;
      document.getElementById('confirm-modal').classList.add('hidden');
      resetLocationFields();
    });
  }

  if (fileImportKdbx) {
    fileImportKdbx.addEventListener('change', (e) => {
      const file = e.target.files[0];
      const masterPasswordInput = document.getElementById('master-password-input');
      const password = masterPasswordInput ? masterPasswordInput.value.trim() : '';
      if (!file) return;
      if (!password) {
        alert('Enter the master password before importing.');
        return;
      }
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          await unlockKdbx(reader.result, password);
          await persistActiveDb();
          document.getElementById('auth-modal').classList.add('hidden');
          updateVaultUI();
          await refreshVault();
        } catch (_) {
          alert('Failed to decrypt imported file. Check password.');
        }
      };
      reader.readAsArrayBuffer(file);
    });
  }

  showAuthPrompt();
});