'use strict';

// ═══════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════
const S = {
  me:            null,
  activeContact: null,
  threads:       [],
  pollTimer:     null,
  authMode:      'login',
  rsaPublicKey:  null,
  rsaPrivateKey: null,
  _pendingVault: null,
  lastMsgId:     {},   // { [email]: number }
};

// ── LRU decryption cache (max 500 entries) ─────────────────────
const DEC_CACHE_MAX = 500;
const decCache = new Map();
function decCacheSet(id, val) {
  if (decCache.size >= DEC_CACHE_MAX) {
    // Evict oldest entry (Map preserves insertion order)
    decCache.delete(decCache.keys().next().value);
  }
  decCache.set(id, val);
}

// Rendered message IDs — dedup guard. Cleared on thread switch / burn.
const renderedIds = new Set();

// Public key cache — imported CryptoKey objects, keyed by email
const pubKeyCache = new Map();

// ── Adaptive poll interval ─────────────────────────────────────
// Visible + active:  3 s base, backs off to 10 s when no new msgs
// Hidden (tab away): 30 s flat — restores on visibility change
const POLL_MIN    = 3000;
const POLL_MAX    = 10000;
const POLL_HIDDEN = 30000;
let   _pollInterval = POLL_MIN;
let   _pollSinceActivity = 0;   // consecutive polls with no new messages

function _resetPollInterval() {
  _pollSinceActivity = 0;
  _pollInterval = POLL_MIN;
}

function _backoffPollInterval() {
  _pollSinceActivity++;
  if (_pollSinceActivity >= 3)  _pollInterval = Math.min(_pollInterval * 1.5 | 0, POLL_MAX);
}

function _effectivePoll() {
  return document.hidden ? POLL_HIDDEN : _pollInterval;
}

// ── Speculative encryption ─────────────────────────────────────
let specText    = '';
let specPromise = null;
let specTimer   = null;

function _startSpecEncrypt(txt) {
  clearTimeout(specTimer);
  if (txt !== specText) { specPromise = null; }
  if (!txt) { specText = ''; specPromise = null; _setSpecIndicator(false); return; }

  specTimer = setTimeout(async () => {
    if (!S.activeContact) return;
    specText    = txt;
    specPromise = callChaosKey('/v1/encrypt', {plaintext: txt}).catch(() => null);
    const ok    = await specPromise;
    _setSpecIndicator(!!ok && specText === txt);
  }, 350);
}

function _setSpecIndicator(ready) {
  const el = document.getElementById('spec-indicator');
  if (el) el.classList.toggle('ready', ready);
}

// ═══════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════
const $   = id => document.getElementById(id);
const esc = s  => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const initials = s => (s||'?')[0].toUpperCase();

// Toast dedup: skip if same message shown in last 2 s
let _lastToastMsg = '', _lastToastTs = 0;
function toast(msg, type='ok', dur=3000) {
  const now = Date.now();
  if (msg === _lastToastMsg && now - _lastToastTs < 2000) return;
  _lastToastMsg = msg; _lastToastTs = now;
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${type} show`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), dur);
}

async function api(path, opts={}) {
  const r = await fetch(path, {
    credentials: 'same-origin',
    headers: {'Content-Type':'application/json', ...(opts.headers||{})},
    ...opts,
  });
  const ct = r.headers.get('Content-Type') || '';
  const data = ct.includes('json') ? await r.json() : {error: 'Server error'};
  return {ok: r.ok, status: r.status, data};
}

async function callChaosKey(path, body) {
  const proxyPath = path.replace('/v1/', '/proxy/');
  const {ok, data} = await api(proxyPath, {method:'POST', body:JSON.stringify(body)});
  if (!ok) throw new Error(data.error || 'ChaosKey proxy error');
  return data;
}

// requestAnimationFrame-throttled textarea resize — avoids forced reflow per keystroke
let _rafResize = null;
function autoResize(ta) {
  if (_rafResize) return;
  _rafResize = requestAnimationFrame(() => {
    _rafResize = null;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
  });
}

function fmtTime(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso), now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Today';
  const y = new Date(now); y.setDate(now.getDate()-1);
  if (d.toDateString() === y.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], {month:'short', day:'numeric'});
}
function closeMod(id) { $(id).classList.remove('open'); }

// ═══════════════════════════════════════════════
//  RSA / vault helpers
// ═══════════════════════════════════════════════
async function deriveAesKey(password, salt) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'},
    km, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
  );
}

async function genAndRegisterKeys(password, email) {
  const kp = await crypto.subtle.generateKey(
    {name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'},
    true, ['encrypt','decrypt']
  );
  S.rsaPublicKey  = kp.publicKey;
  S.rsaPrivateKey = kp.privateKey;

  const pubRaw  = await crypto.subtle.exportKey('spki', kp.publicKey);
  const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);

  _cachePrivKey(email, privRaw);

  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const aesKey  = await deriveAesKey(password, salt);
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const encPriv = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, privRaw);

  const blob = new Uint8Array(16 + 12 + encPriv.byteLength);
  blob.set(salt, 0); blob.set(iv, 16);
  blob.set(new Uint8Array(encPriv), 28);

  return {
    pubB64:     _toB64(pubRaw),
    encPrivB64: _toB64(blob),
    saltHex:    _toHex(salt),
  };
}

async function decryptVault(encPrivB64, password) {
  const blob = _fromB64(encPrivB64);
  if (blob.length < 29) throw new Error('Vault blob too short');
  const salt    = blob.slice(0, 16);
  const iv      = blob.slice(16, 28);
  const ct      = blob.slice(28);
  const aesKey  = await deriveAesKey(password, salt);
  const privRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv}, aesKey, ct);
  return {privRaw, key: await _importPrivKey(privRaw)};
}

async function loadPrivKeyFromStorage(email) {
  const b64 = localStorage.getItem('bc_priv_' + email);
  if (!b64) return null;
  try {
    const raw = _fromB64(b64);
    return await _importPrivKey(raw);
  } catch(e) {
    localStorage.removeItem('bc_priv_' + email);
    return null;
  }
}

async function importPublicKey(pubB64) {
  return crypto.subtle.importKey('spki', _fromB64(pubB64), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
}

async function rsaEncrypt(plaintext, cryptoKey) {
  const enc = await crypto.subtle.encrypt({name:'RSA-OAEP'}, cryptoKey, new TextEncoder().encode(plaintext));
  return _toB64(enc);
}

async function rsaDecrypt(cipherB64) {
  if (!S.rsaPrivateKey) return null;
  try {
    const dec = await crypto.subtle.decrypt({name:'RSA-OAEP'}, S.rsaPrivateKey, _fromB64(cipherB64));
    return new TextDecoder().decode(dec);
  } catch(e) { return null; }
}

// ── Key cache helpers ──────────────────────────────────────────
async function prefetchContactKey(email) {
  if (pubKeyCache.has(email)) return pubKeyCache.get(email);
  try {
    const {data} = await api(`/user/key?email=${encodeURIComponent(email)}`);
    if (data.key) {
      const key = await importPublicKey(data.key);
      pubKeyCache.set(email, key);
      return key;
    }
  } catch(e) {}
  return null;
}

async function prefetchAllContactKeys(emails) {
  const missing = emails.filter(e => !pubKeyCache.has(e));
  if (!missing.length) return;
  try {
    const {ok, data} = await api('/user/keys_bulk', {
      method: 'POST',
      body: JSON.stringify({emails: missing}),
    });
    if (!ok) return;
    await Promise.all(Object.entries(data).map(async ([email, pubB64]) => {
      if (pubB64 && !pubKeyCache.has(email)) {
        const key = await importPublicKey(pubB64);
        pubKeyCache.set(email, key);
      }
    }));
  } catch(e) {}
}

async function ensureOwnPublicKey() {
  if (S.rsaPublicKey) return;
  if (pubKeyCache.has(S.me.email)) { S.rsaPublicKey = pubKeyCache.get(S.me.email); return; }
  try {
    const {data} = await api(`/user/key?email=${encodeURIComponent(S.me.email)}`);
    if (data.key) {
      S.rsaPublicKey = await importPublicKey(data.key);
      pubKeyCache.set(S.me.email, S.rsaPublicKey);
    }
  } catch(e) {}
}

function _toB64(buf)   { return btoa(String.fromCharCode(...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer || buf))); }
function _fromB64(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }
function _toHex(u8)    { return Array.from(u8).map(b => b.toString(16).padStart(2,'0')).join(''); }
function _cachePrivKey(email, privRaw) {
  try { localStorage.setItem('bc_priv_' + email, _toB64(privRaw)); } catch(e) {}
}
async function _importPrivKey(raw) {
  return crypto.subtle.importKey('pkcs8', raw, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['decrypt']);
}

// ═══════════════════════════════════════════════
//  Auth
// ═══════════════════════════════════════════════
function switchAuthTab(mode) {
  S.authMode = mode;
  $('tab-in').classList.toggle('active', mode==='login');
  $('tab-up').classList.toggle('active', mode==='signup');
  $('field-name').style.display   = mode==='signup' ? 'block' : 'none';
  $('field-ck-key').style.display = mode==='signup' ? 'block' : 'none';
  $('auth-btn').textContent = mode==='login' ? 'Sign in →' : 'Create account →';
  $('auth-err').textContent = '';
}

async function doAuth() {
  const email = $('f-email').value.trim().toLowerCase();
  const pw    = $('f-pw').value;
  const name  = $('f-name').value.trim();
  const ckKey = $('f-ck-key').value.trim();
  const errEl = $('auth-err');
  const btn   = $('auth-btn');

  if (!email || !pw) { errEl.textContent = '⚠ Email and password required'; return; }
  btn.disabled = true; errEl.textContent = 'Generating keys…';

  let pubB64=null, encPrivB64=null, saltHex=null;
  if (S.authMode === 'signup') {
    try {
      const keys = await genAndRegisterKeys(pw, email);
      pubB64 = keys.pubB64; encPrivB64 = keys.encPrivB64; saltHex = keys.saltHex;
      errEl.textContent = 'Creating account…';
    } catch(e) {
      errEl.textContent = '⚠ Key generation failed: ' + e.message;
      btn.disabled = false; return;
    }
  } else {
    errEl.textContent = 'Signing in…';
  }

  const path = S.authMode === 'signup' ? '/auth/signup' : '/auth/login';
  const body = S.authMode === 'signup'
    ? {email, password:pw, name, chaoskey_api_key:ckKey, public_key:pubB64, encrypted_private_key:encPrivB64, vault_salt:saltHex}
    : {email, password:pw};

  const {ok, data} = await api(path, {method:'POST', body:JSON.stringify(body)});
  if (!ok) {
    errEl.textContent = '⚠ ' + (data.error || 'Authentication failed');
    btn.disabled = false; return;
  }

  S.me = {email: data.email, name: data.name, color: data.color};

  if (S.authMode === 'login') {
    await _resolvePrivateKey(pw, data);
    if (data.public_key) {
      try { S.rsaPublicKey = await importPublicKey(data.public_key); pubKeyCache.set(data.email, S.rsaPublicKey); } catch(e) {}
    }
  } else {
    if (S.rsaPublicKey) pubKeyCache.set(email, S.rsaPublicKey);
  }

  errEl.textContent = '';
  btn.disabled = false;
  enterApp(data);
}

async function _resolvePrivateKey(password, data) {
  S.rsaPrivateKey = await loadPrivKeyFromStorage(data.email);
  if (S.rsaPrivateKey) return;

  if (data.encrypted_private_key && data.vault_salt) {
    S._pendingVault = {encrypted_private_key: data.encrypted_private_key};
    if (password) {
      try {
        const {privRaw, key} = await decryptVault(data.encrypted_private_key, password);
        S.rsaPrivateKey = key;
        _cachePrivKey(data.email, privRaw);
        toast('🔑 Keys synced from vault', 'ok', 4000);
        return;
      } catch(e) { _showVaultPwModal(); return; }
    }
    _showVaultPwModal();
  } else if (!data.encrypted_private_key) {
    showRekeyModal('missing');
  }
}

async function _resolvePrivateKeyNoPassword(data) {
  S.rsaPrivateKey = await loadPrivKeyFromStorage(data.email);
  if (S.rsaPrivateKey) return;
  if (data.encrypted_private_key) {
    S._pendingVault = {encrypted_private_key: data.encrypted_private_key};
    _showVaultPwModal();
  } else {
    showRekeyModal('missing');
  }
}

function _showVaultPwModal() {
  $('vault-pw-input').value = '';
  $('vault-pw-err').textContent = '';
  $('vault-pw-modal').classList.add('open');
  setTimeout(() => $('vault-pw-input').focus(), 150);
}

async function executeVaultDecrypt() {
  const pw  = $('vault-pw-input').value;
  const btn = $('vault-pw-btn');
  const err = $('vault-pw-err');
  if (!pw) { err.textContent = '⚠ Password required'; return; }
  btn.disabled = true; btn.textContent = 'Unlocking…'; err.textContent = '';
  try {
    const vault = S._pendingVault;
    if (!vault || !vault.encrypted_private_key) throw new Error('No vault data');
    const {privRaw, key} = await decryptVault(vault.encrypted_private_key, pw);
    S.rsaPrivateKey = key;
    _cachePrivKey(S.me.email, privRaw);
    closeMod('vault-pw-modal');
    renderStatusBar();
    toast('🔑 Keys unlocked — messages loading…', 'ok', 4000);
    if (S.activeContact) {
      S.lastMsgId[S.activeContact.email] = 0;
      $('messages-area').innerHTML = '';
      renderedIds.clear();
      await loadThread(S.activeContact.email, true);
    }
  } catch(e) {
    err.textContent = '⚠ Wrong password or corrupted vault';
  } finally { btn.disabled = false; btn.textContent = 'Unlock'; }
}

async function doLogout() {
  await api('/auth/logout', {method:'POST'});
  S.rsaPublicKey = null; S.rsaPrivateKey = null; S._pendingVault = null;
  clearTimeout(S.pollTimer);
  decCache.clear(); pubKeyCache.clear();
  location.reload();
}

async function checkSession() {
  const {ok, data} = await api('/auth/me');
  if (ok && data.authenticated) {
    S.me = {email: data.email, name: data.name, color: data.color};
    await _resolvePrivateKeyNoPassword(data);
    if (data.public_key) {
      try { S.rsaPublicKey = await importPublicKey(data.public_key); pubKeyCache.set(data.email, S.rsaPublicKey); } catch(e) {}
    }
    enterApp(data);
  }
}

// ═══════════════════════════════════════════════
//  App shell
// ═══════════════════════════════════════════════
function enterApp(data={}) {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('my-avatar').textContent = initials(S.me.name);
  $('my-avatar').style.background = S.me.color;
  $('my-name').textContent  = S.me.name;
  $('my-email').textContent = S.me.email;
  renderStatusBar(data);
  loadInbox();

  // Adaptive poll loop — uses setTimeout so each interval can be dynamic
  function schedulePoll() {
    S.pollTimer = setTimeout(async () => {
      let gotNew = false;
      await loadInbox();
      if (S.activeContact) gotNew = await loadThread(S.activeContact.email, false);
      if (gotNew) _resetPollInterval(); else _backoffPollInterval();
      schedulePoll();
    }, _effectivePoll());
  }
  schedulePoll();

  // Re-sync poll speed when tab becomes visible again
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      clearTimeout(S.pollTimer);
      _resetPollInterval();
      // Immediate refresh on return
      loadInbox();
      if (S.activeContact) loadThread(S.activeContact.email, false);
      schedulePoll();
    }
  }, {once: false});
}

function renderStatusBar(data={}) {
  const el = $('status-bar');
  const hasCk = data.has_ck_key ?? true;
  let html = '';
  if (hasCk && data.key_prefix) {
    html += `<div class="bar-item bar-ok">⚿ ${esc(data.key_prefix)}<button class="bar-btn" onclick="$('key-modal').classList.add('open')">update</button></div>`;
  } else if (!hasCk) {
    html += `<div class="bar-item bar-warn">⚠ No ChaosKey key<button class="bar-btn" onclick="$('key-modal').classList.add('open')">add →</button></div>`;
  }
  if (S.rsaPrivateKey) {
    html += `<div class="bar-item bar-ok">🔑 RSA keys ready · cross-device E2EE</div>`;
  } else {
    html += `<div class="bar-item bar-warn">⚠ Keys not loaded<button class="bar-btn" onclick="_showVaultPwModal()">unlock →</button></div>`;
  }
  el.innerHTML = html;
}

// ═══════════════════════════════════════════════
//  Inbox / threads
// ═══════════════════════════════════════════════
let _lastInboxHash = '';

async function loadInbox() {
  const {ok, data} = await api('/msg/inbox');
  if (!ok || !Array.isArray(data)) return;

  const hash = data.map(t => t.contact + t.total).join('|');
  const changed = hash !== _lastInboxHash;
  _lastInboxHash = hash;

  S.threads = data;
  // Use DocumentFragment for batch DOM insertion — avoids N reflows
  if (changed) {
    renderThreadList();
    prefetchAllContactKeys(data.map(t => t.contact));
  }
}

function renderThreadList() {
  const el = $('thread-list');
  if (!S.threads.length) {
    el.innerHTML = `<div class="no-threads">No conversations yet.<br>Search for a user above.</div>`;
    return;
  }
  const frag = document.createDocumentFragment();
  for (const t of S.threads) {
    const div = document.createElement('div');
    div.className = `thread-item${S.activeContact?.email===t.contact?' active':''}`;
    div.onclick = () => openThread(t.contact, t.name, t.color);
    div.innerHTML = `
      <div class="avatar" style="background:${t.color}">${initials(t.name)}</div>
      <div class="thread-info">
        <div class="thread-name">${esc(t.name)}</div>
        <div class="thread-email">${esc(t.contact)}</div>
      </div>
      <div class="thread-time">${fmtDate(t.last_at)}</div>`;
    frag.appendChild(div);
  }
  el.innerHTML = '';
  el.appendChild(frag);
}

async function onSearchInput(val) {
  const res = $('search-results');
  if (!val || val.length < 3) { res.classList.remove('open'); return; }
  const {ok, data} = await api('/msg/search_user?q=' + encodeURIComponent(val));
  if (!ok || !data.length) { res.classList.remove('open'); return; }
  const frag = document.createDocumentFragment();
  for (const u of data) {
    const div = document.createElement('div');
    div.className = 'search-result-item';
    div.onclick = () => openThread(u.email, u.name, u.color);
    div.innerHTML = `
      <div class="avatar" style="background:${u.color};width:28px;height:28px;font-size:.75rem">${initials(u.name)}</div>
      <div class="sr-info"><div class="sr-name">${esc(u.name)}</div><div class="sr-email">${esc(u.email)}</div></div>`;
    frag.appendChild(div);
  }
  res.innerHTML = '';
  res.appendChild(frag);
  res.classList.add('open');
}
function closeSearch() { $('search-results').classList.remove('open'); }

// ═══════════════════════════════════════════════
//  Thread view
// ═══════════════════════════════════════════════
function openThread(email, name, color) {
  S.activeContact = {email, name, color};
  $('contact-name').textContent   = name;
  $('contact-email').textContent  = email;
  $('contact-avatar').textContent = initials(name);
  $('contact-avatar').style.background = color;
  $('empty-state').style.display = 'none';
  $('chat-view').classList.add('active');
  $('search-input').value = '';
  closeSearch();
  renderThreadList();

  // Key is almost certainly already in pubKeyCache from inbox bulk-load
  // — prefetchContactKey is a no-op cache hit in that case
  prefetchContactKey(email);

  S.lastMsgId[email] = 0;
  renderedIds.clear();

  const area = $('messages-area');
  area.innerHTML = '';
  area.dataset.contact = email;

  loadThread(email, true);

  specText = ''; specPromise = null; _setSpecIndicator(false);
  $('compose-input').focus();

  // Reset poll backoff when user opens a thread
  _resetPollInterval();
}

/**
 * Returns true if any new messages were rendered (used for poll backoff).
 */
async function loadThread(email, scrollToBottom=false) {
  const since = S.lastMsgId[email] || 0;
  const {ok, data} = await api(`/msg/thread?with=${encodeURIComponent(email)}&since=${since}`);
  if (!ok || !Array.isArray(data)) return false;

  const newMsgs = data.filter(m => !renderedIds.has(m.id));
  if (!newMsgs.length) return false;

  const maxId = Math.max(...data.map(m => m.id));
  if (maxId > (S.lastMsgId[email] || 0)) S.lastMsgId[email] = maxId;

  // Mark rendered BEFORE async decryption to prevent concurrent poll double-render
  newMsgs.forEach(m => renderedIds.add(m.id));

  const resolved = await Promise.all(newMsgs.map(async m => {
    if (decCache.has(m.id)) return {id: m.id, from: m.from, sent_at: m.sent_at, text: decCache.get(m.id)};

    let text = '[Decryption failed]';
    if (!S.rsaPrivateKey) {
      text = '[Keys not loaded — unlock vault to read]';
    } else if (!m.ciphertext || !m.nonce) {
      text = '[Missing encrypted data]';
    } else {
      const isMine  = m.from === S.me.email;
      const wrapped = isMine ? m.sender_enc_key : m.rsa_enc_key;
      if (!wrapped) {
        text = isMine ? '[Sent before self-wrap]' : '[Missing encrypted key]';
      } else {
        try {
          const rawEncKey = await rsaDecrypt(wrapped);
          if (!rawEncKey) {
            text = '[RSA unwrap failed — wrong device or rotated keys]';
          } else {
            const dec = await callChaosKey('/v1/decrypt', {
              ciphertext:     m.ciphertext,
              nonce:          m.nonce,
              encryption_key: rawEncKey,
            });
            text = dec.plaintext ?? '[Empty]';
            decCacheSet(m.id, text);
          }
        } catch(e) { text = `[${e.message || 'Decryption error'}]`; }
      }
    }
    return {id: m.id, from: m.from, sent_at: m.sent_at, text};
  }));

  const area = $('messages-area');
  if (area.dataset.contact !== email) return false;

  // Batch all new bubbles into a single DocumentFragment — one DOM insertion
  const frag = document.createDocumentFragment();
  let confirmedOptimistic = false;

  for (const m of resolved) {
    const pendingEl = area.querySelector(`[data-pending="${m.id}"]`);
    if (pendingEl) {
      pendingEl.removeAttribute('data-pending');
      pendingEl.classList.remove('optimistic');
      pendingEl.querySelector('.msg-meta').textContent = fmtTime(m.sent_at);
      pendingEl.querySelector('.e2ee-tag').textContent = '⚿ ChaosKey + RSA-OAEP';
      confirmedOptimistic = true;
      continue;
    }

    const mine = m.from === S.me.email;
    const isErr = m.text.startsWith('[');
    const el = document.createElement('div');
    el.className = `msg-group ${mine ? 'mine' : 'theirs'}`;
    el.innerHTML = `
      <div class="bubble${isErr ? ' err-bubble' : ''}">${esc(m.text)}</div>
      <div class="msg-meta">${fmtTime(m.sent_at)}</div>
      <div class="e2ee-tag">⚿ ChaosKey + RSA-OAEP</div>`;
    frag.appendChild(el);
  }

  if (frag.childNodes.length > 0) area.appendChild(frag);

  if (scrollToBottom || _isNearBottom(area)) area.scrollTop = area.scrollHeight;
  return true;
}

function _isNearBottom(el) {
  return el.scrollHeight - el.scrollTop - el.clientHeight < 120;
}

function onComposeInput(ta) {
  autoResize(ta);
  _startSpecEncrypt(ta.value.trim());
}

// ═══════════════════════════════════════════════
//  Send  (optimistic + speculative)
// ═══════════════════════════════════════════════
async function sendMessage() {
  const inp = $('compose-input');
  const txt = inp.value.trim();
  if (!txt || !S.activeContact) return;

  const btn = $('send-btn');
  btn.disabled = true;

  // ── OPTIMISTIC BUBBLE ──────────────────────────────────────
  const area = $('messages-area');
  const optEl = document.createElement('div');
  optEl.className = 'msg-group mine optimistic';
  optEl.dataset.text = txt;
  optEl.innerHTML = `
    <div class="bubble">${esc(txt)}</div>
    <div class="msg-meta">${fmtTime(new Date().toISOString())}</div>
    <div class="e2ee-tag">⚿ encrypting…</div>`;
  area.appendChild(optEl);
  area.scrollTop = area.scrollHeight;

  inp.value = ''; inp.style.height = 'auto';
  specText = ''; specPromise = null; _setSpecIndicator(false);

  // Reset poll backoff on send — we want fast polling now
  _resetPollInterval();

  try {
    const contactEmail = S.activeContact.email;

    // Kick off key fetches in parallel with potential spec encrypt
    const [, recipPubKey] = await Promise.all([
      ensureOwnPublicKey(),
      prefetchContactKey(contactEmail),
    ]);
    if (!S.rsaPublicKey)  throw new Error('Your public key missing — log in again');
    if (!recipPubKey) throw new Error('Recipient has no public key — they need to log in first');

    // Use speculative result if available, else fresh call
    let ck;
    if (specText === txt && specPromise) {
      ck = await specPromise;
      if (!ck) throw new Error('Speculative encrypt failed, retrying…');
    } else {
      ck = await callChaosKey('/v1/encrypt', {plaintext: txt});
    }

    const [rsa_enc_key, sender_enc_key] = await Promise.all([
      rsaEncrypt(ck.encryption_key, recipPubKey),
      rsaEncrypt(ck.encryption_key, S.rsaPublicKey),
    ]);

    const {ok, data} = await api('/msg/send', {
      method: 'POST',
      body: JSON.stringify({
        recipient: contactEmail,
        ciphertext: ck.ciphertext,
        nonce: ck.nonce,
        rsa_enc_key,
        sender_enc_key,
      }),
    });
    if (!ok) throw new Error(data.error || 'Send failed');

    // Register in decCache AND renderedIds immediately
    // so the next poll never fetches or re-renders this message
    decCacheSet(data.id, txt);
    renderedIds.add(data.id);

    // Tag the optimistic bubble with the confirmed server id
    optEl.dataset.pending = data.id;

    // Confirm optimistic bubble
    if (optEl.parentNode) {
      optEl.classList.remove('optimistic');
      optEl.removeAttribute('data-pending');
      optEl.querySelector('.e2ee-tag').textContent = '⚿ ChaosKey + RSA-OAEP';
      const metaEl = optEl.querySelector('.msg-meta');
      if (metaEl) metaEl.textContent = fmtTime(data.sent_at);
    }

    // Update incremental cursor
    if (!S.lastMsgId[contactEmail] || data.id > S.lastMsgId[contactEmail]) {
      S.lastMsgId[contactEmail] = data.id;
    }

    // Update inbox thread list counter locally without a network round-trip
    const thr = S.threads.find(t => t.contact === contactEmail);
    if (thr) { thr.total++; thr.last_at = data.sent_at; }
    // Re-render thread list (cheap — just DOM, no fetch)
    renderThreadList();

  } catch(e) {
    if (optEl.parentNode) optEl.remove();
    inp.value = txt;
    autoResize(inp);
    toast('✗ ' + e.message, 'err');
  } finally {
    btn.disabled = false;
    inp.focus();
  }
}

// ═══════════════════════════════════════════════
//  Burn thread  — INSTANT
// ═══════════════════════════════════════════════
function confirmBurn() {
  if (!S.activeContact) return;
  $('burn-modal-text').textContent = `Burn all messages with ${S.activeContact.name}? This cannot be undone.`;
  $('burn-modal').classList.add('open');
}

async function executeBurn() {
  closeMod('burn-modal');
  if (!S.activeContact) return;
  const contact = S.activeContact.email;

  const area = $('messages-area');
  area.innerHTML = `<div style="text-align:center;color:var(--dust);font-family:'Fira Code',monospace;font-size:.73rem;margin-top:2rem">No messages yet.</div>`;
  area.dataset.contact = contact;

  S.lastMsgId[contact] = 0;
  renderedIds.clear();
  decCache.clear();

  toast('🔥 Thread burned', 'ok');

  api('/msg/burn', {method:'POST', body:JSON.stringify({contact})}).then(({ok}) => {
    if (!ok) toast('⚠ Burn failed on server — refresh to resync', 'err', 5000);
    else loadInbox();
  });
}

// ═══════════════════════════════════════════════
//  ChaosKey key modal
// ═══════════════════════════════════════════════
async function saveUpdatedKey() {
  const val   = $('modal-ck-input').value.trim();
  const errEl = $('key-modal-err');
  if (!val || !val.startsWith('ck_live_')) { errEl.textContent = '⚠ Key must start with ck_live_'; return; }
  const {ok, data} = await api('/auth/update_ck_key', {method:'POST', body:JSON.stringify({chaoskey_api_key:val})});
  if (ok) {
    closeMod('key-modal');
    $('modal-ck-input').value = '';
    toast('⚿ ChaosKey API key updated', 'ok');
    renderStatusBar({has_ck_key:true, key_prefix: data.key_prefix});
  } else {
    errEl.textContent = '⚠ ' + (data.error || 'Update failed');
  }
}

// ═══════════════════════════════════════════════
//  Re-key flow
// ═══════════════════════════════════════════════
function showRekeyModal(reason='missing') {
  $('rekey-modal-title').textContent = reason==='failed' ? 'Generate new keys' : 'No key vault found';
  $('rekey-modal-desc').textContent  = reason==='failed'
    ? 'Vault decryption failed. Generate a fresh keypair — old messages won\'t be recoverable, but new messages will work normally.'
    : 'No key vault found. Enter your password to generate a fresh RSA keypair.';
  $('rekey-modal-err').textContent   = '';
  $('rekey-pw-input').value          = '';
  $('rekey-modal').classList.add('open');
  setTimeout(() => $('rekey-pw-input').focus(), 150);
}

async function executeRekey() {
  const pw    = $('rekey-pw-input').value;
  const errEl = $('rekey-modal-err');
  const btn   = $('rekey-confirm-btn');
  if (!pw)   { errEl.textContent = '⚠ Password required'; return; }
  if (!S.me) { errEl.textContent = '⚠ Not logged in'; return; }

  btn.disabled = true; btn.textContent = 'Generating…'; errEl.textContent = '';
  try {
    const {pubB64, encPrivB64, saltHex} = await genAndRegisterKeys(pw, S.me.email);
    const {ok, data} = await api('/auth/rekey', {
      method: 'POST',
      body: JSON.stringify({password:pw, public_key:pubB64, encrypted_private_key:encPrivB64, vault_salt:saltHex}),
    });
    if (!ok) { errEl.textContent = '⚠ ' + (data.error || 'Re-key failed'); return; }
    closeMod('rekey-modal');
    decCache.clear();
    pubKeyCache.set(S.me.email, S.rsaPublicKey);
    renderStatusBar({has_ck_key: !!S.me, key_prefix: null});
    toast('🔑 New RSA keys generated and saved', 'ok', 5000);
  } catch(e) {
    errEl.textContent = '⚠ ' + (e.message || 'Unknown error');
  } finally { btn.disabled = false; btn.textContent = 'Generate keys'; }
}

// ═══════════════════════════════════════════════
//  Boot
// ═══════════════════════════════════════════════
checkSession();
