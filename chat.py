
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:transparent}
.shell{display:flex;height:600px;border:0.5px solid var(--color-border-tertiary);border-radius:var(--border-radius-lg);overflow:hidden;background:var(--color-background-primary)}
.sidebar{width:220px;border-right:0.5px solid var(--color-border-tertiary);display:flex;flex-direction:column;flex-shrink:0;background:var(--color-background-secondary)}
.sidebar-top{padding:14px 12px 10px;border-bottom:0.5px solid var(--color-border-tertiary)}
.app-name{font-size:13px;font-weight:500;color:var(--color-text-primary);display:flex;align-items:center;gap:8px}
.fire-dot{width:10px;height:10px;border-radius:50%;background:#e24b4a;flex-shrink:0}
.key-bar{margin-top:8px;padding:6px 8px;background:var(--color-background-primary);border:0.5px solid var(--color-border-tertiary);border-radius:var(--border-radius-md);cursor:pointer}
.key-bar-label{font-size:10px;color:var(--color-text-tertiary);margin-bottom:3px}
.key-bar-val{font-size:11px;font-family:var(--font-mono);color:var(--color-text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.timer-row{display:flex;align-items:center;gap:6px;margin-top:8px}
.timer-track{flex:1;height:2px;background:var(--color-border-tertiary);border-radius:2px;overflow:hidden}
.timer-fill{height:100%;background:#639922;border-radius:2px;transition:width 1s linear}
.timer-fill.mid{background:#ba7517}
.timer-fill.low{background:#e24b4a}
.timer-text{font-size:10px;font-family:var(--font-mono);color:var(--color-text-secondary);min-width:22px;text-align:right}
.contacts{flex:1;overflow-y:auto;padding:6px}
.contact-item{display:flex;align-items:center;gap:8px;padding:7px 8px;border-radius:var(--border-radius-md);cursor:pointer;transition:background .15s}
.contact-item:hover,.contact-item.active{background:var(--color-background-primary)}
.avatar{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:500;flex-shrink:0}
.av-a{background:#EEEDFE;color:#3C3489}
.av-b{background:#E1F5EE;color:#085041}
.av-c{background:#FAEEDA;color:#633806}
.contact-name{font-size:13px;color:var(--color-text-primary);font-weight:500}
.contact-sub{font-size:11px;color:var(--color-text-secondary)}
.new-contact-btn{margin:6px;padding:7px;border:0.5px dashed var(--color-border-secondary);border-radius:var(--border-radius-md);background:none;color:var(--color-text-secondary);font-size:12px;cursor:pointer;width:calc(100% - 12px);text-align:center;transition:background .15s}
.new-contact-btn:hover{background:var(--color-background-primary)}
.chat-area{flex:1;display:flex;flex-direction:column;min-width:0}
.chat-header{padding:12px 16px;border-bottom:0.5px solid var(--color-border-tertiary);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.chat-header-left{display:flex;align-items:center;gap:10px}
.chat-header-name{font-size:14px;font-weight:500;color:var(--color-text-primary)}
.chat-header-sub{font-size:11px;color:var(--color-text-secondary)}
.enc-badge{font-size:10px;padding:2px 7px;border-radius:100px;background:#EAF3DE;color:#27500A;border:0.5px solid #97C459;font-family:var(--font-mono)}
.messages{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px}
.msg-row{display:flex;gap:8px;align-items:flex-end}
.msg-row.mine{flex-direction:row-reverse}
.msg-avatar{width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:500;flex-shrink:0}
.bubble{max-width:68%;padding:8px 12px;border-radius:14px;font-size:13px;line-height:1.5;position:relative}
.bubble.theirs{background:var(--color-background-secondary);color:var(--color-text-primary);border-radius:4px 14px 14px 14px}
.bubble.mine{background:#534AB7;color:#EEEDFE;border-radius:14px 4px 14px 14px}
.bubble-time{font-size:10px;margin-top:3px;opacity:0.6}
.bubble-enc-indicator{display:flex;align-items:center;gap:4px;font-size:10px;margin-top:4px;font-family:var(--font-mono)}
.enc-dot{width:5px;height:5px;border-radius:50%;background:#639922;flex-shrink:0}
.enc-dot.expired{background:#e24b4a}
.burn-notice{text-align:center;font-size:11px;color:var(--color-text-tertiary);padding:4px 10px;background:var(--color-background-secondary);border-radius:100px;border:0.5px solid var(--color-border-tertiary);margin:4px auto;font-family:var(--font-mono)}
.input-area{padding:12px 16px;border-top:0.5px solid var(--color-border-tertiary);display:flex;gap:8px;align-items:flex-end;flex-shrink:0}
.input-area textarea{flex:1;resize:none;border:0.5px solid var(--color-border-secondary);border-radius:var(--border-radius-lg);padding:8px 12px;font-size:13px;font-family:system-ui,sans-serif;background:var(--color-background-secondary);color:var(--color-text-primary);outline:none;line-height:1.5;max-height:80px;overflow-y:auto}
.input-area textarea:focus{border-color:var(--color-border-primary)}
.send-btn{width:36px;height:36px;border-radius:50%;border:none;background:#534AB7;color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:14px;transition:opacity .15s}
.send-btn:hover{opacity:0.85}
.send-btn:disabled{opacity:0.4;cursor:not-allowed}
.empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--color-text-tertiary);font-size:13px;gap:6px}
.setup-overlay{position:absolute;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:10;border-radius:var(--border-radius-lg)}
.setup-card{background:var(--color-background-primary);border:0.5px solid var(--color-border-tertiary);border-radius:var(--border-radius-lg);padding:20px 24px;width:340px}
.setup-card h3{font-size:15px;font-weight:500;color:var(--color-text-primary);margin-bottom:4px}
.setup-card p{font-size:12px;color:var(--color-text-secondary);margin-bottom:16px;line-height:1.5}
.setup-field{margin-bottom:10px}
.setup-field label{font-size:11px;color:var(--color-text-secondary);display:block;margin-bottom:4px}
.setup-field input{width:100%;padding:7px 10px;border:0.5px solid var(--color-border-secondary);border-radius:var(--border-radius-md);background:var(--color-background-secondary);color:var(--color-text-primary);font-size:12px;font-family:var(--font-mono);outline:none}
.setup-field input:focus{border-color:var(--color-border-primary)}
.setup-actions{display:flex;gap:8px;margin-top:14px}
.btn-save{flex:1;padding:8px;background:#534AB7;color:#fff;border:none;border-radius:var(--border-radius-md);font-size:13px;font-weight:500;cursor:pointer}
.btn-cancel{padding:8px 14px;background:none;color:var(--color-text-secondary);border:0.5px solid var(--color-border-secondary);border-radius:var(--border-radius-md);font-size:13px;cursor:pointer}
.add-contact-card{background:var(--color-background-primary);border:0.5px solid var(--color-border-tertiary);border-radius:var(--border-radius-lg);padding:20px 24px;width:320px}
.add-contact-card h3{font-size:15px;font-weight:500;color:var(--color-text-primary);margin-bottom:12px}
.status-dot{width:6px;height:6px;border-radius:50%;display:inline-block;margin-right:4px}
.status-ok{background:#639922}
.status-err{background:#e24b4a}
.cfg-btn{padding:4px 8px;background:none;border:0.5px solid var(--color-border-secondary);border-radius:var(--border-radius-md);font-size:11px;color:var(--color-text-secondary);cursor:pointer;transition:background .15s}
.cfg-btn:hover{background:var(--color-background-secondary)}
</style>
<h2 class="sr-only">Burn After Reading — encrypted chat app powered by ChaosKey rotating entropy keys</h2>
<div style="position:relative">
<div class="shell" id="shell">

  <div class="sidebar">
    <div class="sidebar-top">
      <div class="app-name">
        <div class="fire-dot"></div>
        BurnChat
      </div>
      <div class="key-bar" onclick="openSetup()" title="Click to configure">
        <div class="key-bar-label">server &amp; key</div>
        <div class="key-bar-val" id="key-preview">click to configure →</div>
      </div>
      <div class="timer-row">
        <div class="timer-track"><div class="timer-fill" id="timer-fill"></div></div>
        <span class="timer-text" id="timer-text">10s</span>
      </div>
    </div>
    <div class="contacts" id="contacts-list"></div>
    <button class="new-contact-btn" onclick="openAddContact()">+ add contact</button>
  </div>

  <div class="chat-area">
    <div class="chat-header" id="chat-header" style="display:none">
      <div class="chat-header-left">
        <div class="avatar" id="chat-avatar" style="width:28px;height:28px;font-size:11px"></div>
        <div>
          <div class="chat-header-name" id="chat-name"></div>
          <div class="chat-header-sub" id="chat-sub"></div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span class="enc-badge">E2E encrypted</span>
        <button class="cfg-btn" onclick="openSetup()">settings</button>
      </div>
    </div>
    <div id="messages" class="messages">
      <div class="empty-state" id="empty-state">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--color-text-tertiary)" stroke-width="1.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        <span>Select a contact to start chatting</span>
        <span style="font-size:11px">Messages burn after the key rotates</span>
      </div>
    </div>
    <div class="input-area" id="input-area" style="display:none">
      <textarea id="msg-input" rows="1" placeholder="Type a secret message…" onkeydown="handleKey(event)" oninput="autoResize(this)"></textarea>
      <button class="send-btn" id="send-btn" onclick="sendMessage()" title="Encrypt &amp; send">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
      </button>
    </div>
  </div>
</div>

<div class="setup-overlay" id="setup-overlay">
  <div class="setup-card">
    <h3>Connect to ChaosKey</h3>
    <p>Enter your server URL and API key to enable end-to-end encrypted messaging.</p>
    <div class="setup-field">
      <label>Server URL</label>
      <input type="text" id="cfg-server" placeholder="https://your-app.onrender.com">
    </div>
    <div class="setup-field">
      <label>API key</label>
      <input type="text" id="cfg-key" placeholder="ck_live_…">
    </div>
    <div class="setup-field">
      <label>Your name</label>
      <input type="text" id="cfg-name" placeholder="Alice">
    </div>
    <div id="cfg-status" style="font-size:11px;color:var(--color-text-secondary);min-height:14px;margin-top:4px"></div>
    <div class="setup-actions">
      <button class="btn-cancel" onclick="closeSetup()">cancel</button>
      <button class="btn-save" onclick="saveSetup()">save &amp; connect</button>
    </div>
  </div>
</div>

<div class="setup-overlay" id="add-contact-overlay" style="display:none">
  <div class="add-contact-card">
    <h3>Add contact</h3>
    <div class="setup-field">
      <label>Name</label>
      <input type="text" id="nc-name" placeholder="Bob">
    </div>
    <div id="nc-status" style="font-size:11px;color:var(--color-text-secondary);min-height:14px;margin-top:4px"></div>
    <div class="setup-actions">
      <button class="btn-cancel" onclick="closeAddContact()">cancel</button>
      <button class="btn-save" onclick="addContact()">add</button>
    </div>
  </div>
</div>
</div>

<script>
const AVATAR_COLORS = [
  {bg:'#EEEDFE',color:'#3C3489'},
  {bg:'#E1F5EE',color:'#085041'},
  {bg:'#FAEEDA',color:'#633806'},
  {bg:'#FBEAF0',color:'#72243E'},
  {bg:'#E6F1FB',color:'#0C447C'},
];

let cfg = JSON.parse(localStorage.getItem('bc_cfg') || '{"server":"","key":"","name":"You"}');
let contacts = JSON.parse(localStorage.getItem('bc_contacts') || '[]');
let threads = JSON.parse(localStorage.getItem('bc_threads') || '{}');
let activeContact = null;

function saveAll() {
  localStorage.setItem('bc_cfg', JSON.stringify(cfg));
  localStorage.setItem('bc_contacts', JSON.stringify(contacts));
  localStorage.setItem('bc_threads', JSON.stringify(threads));
}

function initials(name) {
  return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0,2);
}

function avatarStyle(idx) {
  const c = AVATAR_COLORS[idx % AVATAR_COLORS.length];
  return `background:${c.bg};color:${c.color}`;
}

function renderContacts() {
  const list = document.getElementById('contacts-list');
  list.innerHTML = '';
  contacts.forEach((c, i) => {
    const msgs = threads[c.id] || [];
    const last = msgs[msgs.length-1];
    const div = document.createElement('div');
    div.className = 'contact-item' + (activeContact && activeContact.id === c.id ? ' active' : '');
    div.innerHTML = `
      <div class="avatar" style="${avatarStyle(i)}">${initials(c.name)}</div>
      <div style="min-width:0">
        <div class="contact-name">${c.name}</div>
        <div class="contact-sub" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${last ? (last.mine ? 'You: ' : '') + '[encrypted]' : 'no messages yet'}</div>
      </div>`;
    div.onclick = () => selectContact(c, i);
    list.appendChild(div);
  });
}

function selectContact(contact, idx) {
  activeContact = contact;
  renderContacts();
  document.getElementById('chat-header').style.display = 'flex';
  document.getElementById('input-area').style.display = 'flex';
  document.getElementById('empty-state').style.display = 'none';
  const av = document.getElementById('chat-avatar');
  av.textContent = initials(contact.name);
  av.style.cssText = avatarStyle(idx) + ';width:28px;height:28px;font-size:11px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:500;flex-shrink:0';
  document.getElementById('chat-name').textContent = contact.name;
  document.getElementById('chat-sub').textContent = 'Messages self-destruct on key rotation';
  renderMessages();
  setTimeout(() => {
    const m = document.getElementById('messages');
    m.scrollTop = m.scrollHeight;
  }, 50);
  document.getElementById('msg-input').focus();
}

function renderMessages() {
  const container = document.getElementById('messages');
  const msgs = threads[activeContact.id] || [];
  container.innerHTML = '';
  if (msgs.length === 0) {
    container.innerHTML = `<div style="text-align:center;font-size:12px;color:var(--color-text-tertiary);margin:auto;padding:20px 0">Send your first encrypted message to ${activeContact.name}</div>`;
    return;
  }
  const myName = cfg.name || 'You';
  msgs.forEach((msg, i) => {
    if (msg.type === 'notice') {
      const n = document.createElement('div');
      n.className = 'burn-notice';
      n.textContent = msg.text;
      container.appendChild(n);
      return;
    }
    const row = document.createElement('div');
    row.className = 'msg-row' + (msg.mine ? ' mine' : '');
    const ci = contacts.findIndex(c => c.id === activeContact.id);
    const avStyle = msg.mine ? 'background:#534AB7;color:#EEEDFE' : avatarStyle(ci);
    const avInitials = msg.mine ? initials(myName) : initials(activeContact.name);
    const timeStr = new Date(msg.ts).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    const keyExpired = (Date.now() - msg.ts) > 10000;
    row.innerHTML = `
      <div class="msg-avatar" style="${avStyle}">${avInitials}</div>
      <div>
        <div class="bubble ${msg.mine ? 'mine' : 'theirs'}">
          ${msg.plaintext ? escHtml(msg.plaintext) : '<em style="opacity:0.6">decrypted</em>'}
          <div class="bubble-time">${timeStr}</div>
          <div class="bubble-enc-indicator">
            <div class="enc-dot ${keyExpired ? 'expired' : ''}"></div>
            <span style="opacity:0.6;font-size:10px;font-family:var(--font-mono)">${keyExpired ? 'key rotated' : 'encrypted'}</span>
          </div>
        </div>
      </div>`;
    container.appendChild(row);
  });
  container.scrollTop = container.scrollHeight;
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 80) + 'px';
}

async function apiFetch(path, opts) {
  if (!cfg.server) return { ok: false, data: { error: 'No server configured' }};
  if (!cfg.key)    return { ok: false, data: { error: 'No API key configured' }};
  try {
    const r = await fetch(cfg.server.replace(/\/$/, '') + path, opts);
    let data;
    try { data = await r.json(); } catch(e) { data = { error: 'Non-JSON response' }; }
    return { ok: r.ok, data };
  } catch(e) {
    return { ok: false, data: { error: 'Cannot reach server' }};
  }
}

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !activeContact) return;
  const btn = document.getElementById('send-btn');
  btn.disabled = true;
  input.disabled = true;

  const { ok, data } = await apiFetch('/v1/encrypt', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + cfg.key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ plaintext: text })
  });

  if (ok) {
    if (!threads[activeContact.id]) threads[activeContact.id] = [];
    threads[activeContact.id].push({
      mine: true,
      plaintext: text,
      ciphertext: data.ciphertext,
      nonce: data.nonce,
      encryption_key: data.encryption_key,
      ts: Date.now()
    });
    input.value = '';
    input.style.height = 'auto';
    saveAll();
    renderContacts();
    renderMessages();
  } else {
    showToast('Encryption failed: ' + (data.error || 'unknown error'));
  }
  btn.disabled = false;
  input.disabled = false;
  input.focus();
}

function showToast(msg) {
  const t = document.createElement('div');
  t.style.cssText = 'position:absolute;bottom:60px;left:50%;transform:translateX(-50%);background:#e24b4a;color:#fff;font-size:12px;padding:6px 14px;border-radius:100px;z-index:20;white-space:nowrap';
  t.textContent = msg;
  document.querySelector('[style="position:relative"]').appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

function openSetup() {
  document.getElementById('cfg-server').value = cfg.server || '';
  document.getElementById('cfg-key').value = cfg.key || '';
  document.getElementById('cfg-name').value = cfg.name || '';
  document.getElementById('setup-overlay').style.display = 'flex';
  document.getElementById('cfg-status').textContent = '';
}

function closeSetup() {
  if (cfg.server && cfg.key) document.getElementById('setup-overlay').style.display = 'none';
}

async function saveSetup() {
  const server = document.getElementById('cfg-server').value.trim().replace(/\/$/, '');
  const key    = document.getElementById('cfg-key').value.trim();
  const name   = document.getElementById('cfg-name').value.trim() || 'You';
  const st = document.getElementById('cfg-status');
  if (!server || !key) { st.innerHTML = '<span class="status-dot status-err"></span>Server and API key required'; return; }
  st.innerHTML = '<span class="status-dot" style="background:#ba7517"></span>Connecting…';
  cfg = { server, key, name };
  saveAll();
  const { ok } = await apiFetch('/v1/usage', { headers: { 'Authorization': 'Bearer ' + key }});
  if (ok) {
    st.innerHTML = '<span class="status-dot status-ok"></span>Connected!';
    updateKeyPreview();
    setTimeout(() => document.getElementById('setup-overlay').style.display = 'none', 800);
  } else {
    st.innerHTML = '<span class="status-dot status-err"></span>Could not connect — check server URL and key';
  }
}

function updateKeyPreview() {
  const el = document.getElementById('key-preview');
  if (cfg.key) {
    el.textContent = cfg.key.slice(0, 16) + '…';
    el.style.color = 'var(--color-text-primary)';
  } else {
    el.textContent = 'click to configure →';
    el.style.color = 'var(--color-text-secondary)';
  }
}

function openAddContact() {
  document.getElementById('nc-name').value = '';
  document.getElementById('nc-status').textContent = '';
  document.getElementById('add-contact-overlay').style.display = 'flex';
  setTimeout(() => document.getElementById('nc-name').focus(), 50);
}

function closeAddContact() {
  document.getElementById('add-contact-overlay').style.display = 'none';
}

function addContact() {
  const name = document.getElementById('nc-name').value.trim();
  const st = document.getElementById('nc-status');
  if (!name) { st.textContent = 'Enter a name'; return; }
  const id = 'c_' + Date.now();
  contacts.push({ id, name });
  saveAll();
  renderContacts();
  closeAddContact();
  const idx = contacts.length - 1;
  selectContact(contacts[idx], idx);
}

let timerSec = 10;
function tickTimer() {
  timerSec--;
  if (timerSec <= 0) {
    timerSec = 10;
    if (activeContact) renderMessages();
  }
  const pct = (timerSec / 10) * 100;
  const fill = document.getElementById('timer-fill');
  fill.style.width = pct + '%';
  fill.className = 'timer-fill' + (timerSec <= 3 ? ' low' : timerSec <= 6 ? ' mid' : '');
  document.getElementById('timer-text').textContent = timerSec + 's';
}
const startSec = 10 - (Math.floor(Date.now() / 1000) % 10);
timerSec = startSec;
document.getElementById('timer-fill').style.width = (startSec / 10 * 100) + '%';
setInterval(tickTimer, 1000);

if (cfg.server && cfg.key) {
  updateKeyPreview();
  document.getElementById('setup-overlay').style.display = 'none';
}
renderContacts();

if (contacts.length === 0) {
  contacts = [
    { id: 'demo_alice', name: 'Alice' },
    { id: 'demo_bob',   name: 'Bob'   },
  ];
  threads['demo_alice'] = [
    { mine: false, plaintext: 'Hey! Did you set up the server yet?', ts: Date.now() - 45000 },
    { mine: true,  plaintext: 'Almost — just need to paste the API key.', ts: Date.now() - 30000 },
    { type: 'notice', text: 'key rotated — messages above are locked' },
  ];
  renderContacts();
}
</script>
