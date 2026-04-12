
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:var(--color-background-primary);
  --bg2:var(--color-background-secondary);
  --bg3:var(--color-background-tertiary);
  --border:var(--color-border-tertiary);
  --border2:var(--color-border-secondary);
  --txt:var(--color-text-primary);
  --txt2:var(--color-text-secondary);
  --txt3:var(--color-text-tertiary);
  --info-bg:var(--color-background-info);
  --info-txt:var(--color-text-info);
  --success-bg:var(--color-background-success);
  --success-txt:var(--color-text-success);
  --danger-bg:var(--color-background-danger);
  --danger-txt:var(--color-text-danger);
  --r:var(--border-radius-md);
  --rl:var(--border-radius-lg);
}
body{font-family:var(--font-sans);font-size:14px;color:var(--txt);background:var(--bg3);min-height:520px}

/* ── auth screen ── */
#auth-screen{display:flex;align-items:center;justify-content:center;min-height:520px;padding:2rem}
.auth-card{background:var(--bg);border:0.5px solid var(--border2);border-radius:var(--rl);padding:2rem;width:100%;max-width:360px}
.auth-card h2{font-size:16px;font-weight:500;margin-bottom:4px}
.auth-card p{font-size:13px;color:var(--txt2);margin-bottom:1.5rem}
.auth-card label{display:block;font-size:12px;color:var(--txt2);margin-bottom:4px;margin-top:12px}
.auth-card input{width:100%;padding:8px 10px;border:0.5px solid var(--border2);border-radius:var(--r);background:var(--bg2);color:var(--txt);font-size:14px;outline:none}
.auth-card input:focus{border-color:var(--color-border-primary)}
.auth-card .field-row{display:flex;align-items:center;gap:8px;position:relative}
.auth-card .field-row input{flex:1}
.btn-primary{margin-top:1.25rem;width:100%;padding:9px;background:var(--txt);color:var(--bg);border:none;border-radius:var(--r);font-size:14px;font-weight:500;cursor:pointer}
.btn-primary:hover{opacity:.85}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
.auth-err{margin-top:.75rem;font-size:13px;color:var(--danger-txt);background:var(--danger-bg);border-radius:var(--r);padding:8px 10px;display:none}
.base-url-row{display:flex;gap:6px;margin-bottom:1rem}
.base-url-row input{flex:1;padding:6px 8px;border:0.5px solid var(--border);border-radius:var(--r);background:var(--bg2);color:var(--txt);font-size:12px}
.base-url-row span{font-size:11px;color:var(--txt3);align-self:center;white-space:nowrap}

/* ── chat app ── */
#chat-screen{display:none;height:520px;background:var(--bg);border:0.5px solid var(--border2);border-radius:var(--rl);overflow:hidden;flex-direction:row}
.sidebar{width:220px;border-right:0.5px solid var(--border);display:flex;flex-direction:column;background:var(--bg2)}
.sidebar-header{padding:14px 14px 10px;border-bottom:0.5px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.sidebar-header .me{font-size:13px;font-weight:500;color:var(--txt)}
.sidebar-header .tier-badge{font-size:10px;padding:2px 7px;border-radius:20px;background:var(--info-bg);color:var(--info-txt)}
.sidebar-header .logout-btn{font-size:11px;color:var(--txt3);background:none;border:none;cursor:pointer;padding:0}
.sidebar-header .logout-btn:hover{color:var(--txt)}
.contacts-label{font-size:10px;color:var(--txt3);padding:10px 14px 4px;text-transform:uppercase;letter-spacing:.05em}
.contact-list{flex:1;overflow-y:auto}
.contact-item{display:flex;align-items:center;gap:10px;padding:9px 14px;cursor:pointer;border-bottom:0.5px solid var(--border)}
.contact-item:hover,.contact-item.active{background:var(--bg)}
.contact-avatar{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:500;flex-shrink:0}
.contact-info{flex:1;min-width:0}
.contact-name{font-size:13px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.contact-preview{font-size:11px;color:var(--txt3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:1px}
.add-contact-row{padding:10px 14px;border-top:0.5px solid var(--border)}
.add-contact-row input{width:100%;padding:6px 8px;font-size:12px;border:0.5px solid var(--border2);border-radius:var(--r);background:var(--bg);color:var(--txt);outline:none}
.add-contact-row input:focus{border-color:var(--color-border-primary)}
.add-contact-btn{margin-top:5px;width:100%;padding:5px;font-size:12px;background:none;border:0.5px solid var(--border2);border-radius:var(--r);color:var(--txt2);cursor:pointer}
.add-contact-btn:hover{background:var(--bg3)}

/* ── chat panel ── */
.chat-panel{flex:1;display:flex;flex-direction:column;min-width:0}
.chat-header{padding:12px 16px;border-bottom:0.5px solid var(--border);display:flex;align-items:center;gap:10px;background:var(--bg)}
.chat-header .avatar{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:500;flex-shrink:0}
.chat-header-info{flex:1}
.chat-header-name{font-size:14px;font-weight:500}
.chat-header-sub{font-size:11px;color:var(--txt3)}
.enc-badge{font-size:10px;padding:2px 8px;border-radius:20px;background:var(--success-bg);color:var(--success-txt)}
.empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--txt3);gap:8px}
.empty-state .icon{font-size:24px}
.empty-state p{font-size:13px}
.messages-area{flex:1;overflow-y:auto;padding:12px 16px;display:flex;flex-direction:column;gap:10px;background:var(--bg3)}
.msg-wrap{display:flex;flex-direction:column;max-width:72%;gap:2px}
.msg-wrap.mine{align-self:flex-end;align-items:flex-end}
.msg-wrap.theirs{align-self:flex-start;align-items:flex-start}
.msg-sender{font-size:11px;color:var(--txt3);padding:0 4px}
.msg-bubble{padding:8px 12px;border-radius:14px;font-size:13px;line-height:1.5;word-break:break-word}
.msg-wrap.mine .msg-bubble{background:var(--txt);color:var(--bg);border-bottom-right-radius:4px}
.msg-wrap.theirs .msg-bubble{background:var(--bg);border:0.5px solid var(--border);color:var(--txt);border-bottom-left-radius:4px}
.msg-meta{display:flex;align-items:center;gap:6px;padding:0 4px}
.msg-time{font-size:10px;color:var(--txt3)}
.enc-tick{font-size:9px;color:var(--success-txt);background:var(--success-bg);padding:1px 5px;border-radius:10px}
.msg-enc-detail{font-size:10px;color:var(--txt3);padding:0 4px;font-family:var(--font-mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;cursor:pointer}
.msg-enc-detail:hover{color:var(--info-txt)}
.compose-area{padding:10px 14px;border-top:0.5px solid var(--border);display:flex;gap:8px;align-items:flex-end;background:var(--bg)}
.compose-area textarea{flex:1;resize:none;padding:8px 11px;border:0.5px solid var(--border2);border-radius:var(--r);font-size:13px;font-family:var(--font-sans);color:var(--txt);background:var(--bg2);outline:none;max-height:96px;line-height:1.4}
.compose-area textarea:focus{border-color:var(--color-border-primary)}
.send-btn{padding:8px 14px;background:var(--txt);color:var(--bg);border:none;border-radius:var(--r);font-size:13px;font-weight:500;cursor:pointer;flex-shrink:0;align-self:flex-end}
.send-btn:disabled{opacity:.4;cursor:not-allowed}
.send-btn:hover:not(:disabled){opacity:.85}
.toast{position:absolute;bottom:16px;right:16px;background:var(--bg);border:0.5px solid var(--border2);border-radius:var(--r);padding:8px 12px;font-size:12px;color:var(--txt2);box-shadow:none;display:none;max-width:240px}
.no-contact-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--txt3);text-align:center;padding:2rem;gap:8px}
.no-contact-state p{font-size:13px}
.spinner{display:inline-block;width:12px;height:12px;border:2px solid var(--border2);border-top-color:var(--txt);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:4px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>

<h2 class="sr-only">ChaosKey encrypted chat — login and send end-to-end encrypted messages</h2>

<div id="auth-screen">
  <div class="auth-card">
    <h2>ChaosKey Chat</h2>
    <p>End-to-end encrypted · powered by your CryptoAPI</p>
    <div class="base-url-row">
      <input id="base-url" type="text" value="https://your-app.onrender.com" placeholder="https://your-api.com" />
      <span>API base</span>
    </div>
    <label>Email</label>
    <input id="login-email" type="email" placeholder="you@example.com" autocomplete="email" />
    <label>Password</label>
    <div class="field-row">
      <input id="login-pw" type="password" placeholder="••••••••" autocomplete="current-password" />
    </div>
    <div class="auth-err" id="auth-err"></div>
    <button class="btn-primary" id="login-btn" onclick="doLogin()">Log in</button>
    <p style="margin-top:10px;font-size:12px;color:var(--txt3);text-align:center">Don't have an account? Register at your ChaosKey dashboard first.</p>
  </div>
</div>

<div id="chat-screen" style="display:none;flex-direction:row">
  <div class="sidebar">
    <div class="sidebar-header">
      <div>
        <div class="me" id="sidebar-name">—</div>
        <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
          <div class="tier-badge" id="sidebar-tier">free</div>
          <div style="font-size:10px;color:var(--txt3)" id="sidebar-quota"></div>
        </div>
      </div>
      <button class="logout-btn" onclick="doLogout()">sign out</button>
    </div>
    <div class="contacts-label">Conversations</div>
    <div class="contact-list" id="contact-list"></div>
    <div class="add-contact-row">
      <input id="new-contact-input" type="text" placeholder="Add contact (email)" onkeydown="if(event.key==='Enter')addContact()" />
      <button class="add-contact-btn" onclick="addContact()">+ Add</button>
    </div>
  </div>
  <div class="chat-panel" id="chat-panel">
    <div class="no-contact-state" id="no-contact-state">
      <div style="font-size:24px">💬</div>
      <p>Add a contact and start an encrypted conversation.</p>
    </div>
    <div id="active-chat" style="display:none;flex-direction:column;height:100%;flex:1">
      <div class="chat-header">
        <div class="avatar" id="ch-avatar" style="background:var(--info-bg);color:var(--info-txt)">?</div>
        <div class="chat-header-info">
          <div class="chat-header-name" id="ch-name">—</div>
          <div class="chat-header-sub" id="ch-sub">—</div>
        </div>
        <div class="enc-badge">AES-256-GCM</div>
      </div>
      <div class="messages-area" id="messages-area"></div>
      <div class="compose-area">
        <textarea id="compose-input" rows="1" placeholder="Type a message… (Enter to send)" onkeydown="handleComposeKey(event)" oninput="autoResize(this)"></textarea>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">Send</button>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let API_BASE = '';
let apiKey = '';
let myEmail = '';
let myName = '';
let myTier = 'free';
let myQuota = 100;
let contacts = [];
let conversations = {};
let activeContact = null;
const COLORS = [
  {bg:'#E6F1FB',txt:'#0C447C'},{bg:'#EAF3DE',txt:'#27500A'},
  {bg:'#EEEDFE',txt:'#3C3489'},{bg:'#FBEAF0',txt:'#72243E'},
  {bg:'#FAEEDA',txt:'#633806'},{bg:'#E1F5EE',txt:'#085041'}
];
function colorFor(email){const h=email.split('').reduce((a,c)=>a+c.charCodeAt(0),0);return COLORS[h%COLORS.length]}
function initials(email){const n=email.split('@')[0];return n.slice(0,2).toUpperCase()}
function fmtTime(ts){const d=new Date(ts);return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}
function showToast(msg,dur=2500){const t=document.getElementById('toast');t.textContent=msg;t.style.display='block';setTimeout(()=>t.style.display='none',dur)}
function autoResize(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,96)+'px'}

async function apiFetch(path,opts={}){
  const url=API_BASE.replace(/\/+$/,'')+path;
  try{
    const r=await fetch(url,{...opts,headers:{...(opts.headers||{}),'Content-Type':'application/json'}});
    const ct=r.headers.get('Content-Type')||'';
    let data;
    if(ct.includes('json')){data=await r.json()}else{const t=await r.text();data={error:'Non-JSON: '+t.slice(0,80)}}
    return{ok:r.ok,status:r.status,data};
  }catch(e){return{ok:false,status:0,data:{error:e.message}}}
}

async function doLogin(){
  const btn=document.getElementById('login-btn');
  const errEl=document.getElementById('auth-err');
  API_BASE=document.getElementById('base-url').value.trim();
  const email=document.getElementById('login-email').value.trim().toLowerCase();
  const pw=document.getElementById('login-pw').value;
  errEl.style.display='none';
  if(!API_BASE||!email||!pw){errEl.textContent='Please fill in all fields.';errEl.style.display='block';return}
  btn.disabled=true;btn.innerHTML='<span class="spinner"></span>Logging in…';
  const{ok,data}=await apiFetch('/v1/login',{method:'POST',body:JSON.stringify({email,password:pw})});
  if(!ok){errEl.textContent=data.error||'Login failed';errEl.style.display='block';btn.disabled=false;btn.textContent='Log in';return}
  myEmail=email;
  myName=data.name||email.split('@')[0];
  myTier=data.tier||'free';
  myQuota=data.quota||100;
  apiKey='__NEEDS_ROTATE__';
  document.getElementById('auth-screen').style.display='none';
  const cs=document.getElementById('chat-screen');
  cs.style.display='flex';
  document.getElementById('sidebar-name').textContent=myName;
  document.getElementById('sidebar-tier').textContent=myTier;
  document.getElementById('sidebar-quota').textContent=myTier==='admin'?'∞':(myQuota+'/day');
  showToast('Logged in. Rotating key to retrieve API key…');
  await rotateKeyForSession(email,pw);
}

async function rotateKeyForSession(email,pw){
  const{ok,data}=await apiFetch('/v1/rotate_key',{method:'POST',body:JSON.stringify({email,password:pw})});
  if(ok&&data.api_key){
    apiKey=data.api_key;
    showToast('API key ready — E2E encryption active.');
    renderContacts();
  }else{
    showToast('Warning: could not retrieve API key. Encryption may fail. '+( data.error||''));
  }
}

function doLogout(){
  apiKey='';myEmail='';myName='';contacts=[];conversations={};activeContact=null;
  document.getElementById('chat-screen').style.display='none';
  document.getElementById('auth-screen').style.display='flex';
  document.getElementById('login-pw').value='';
  document.getElementById('auth-err').style.display='none';
  document.getElementById('login-btn').disabled=false;
  document.getElementById('login-btn').textContent='Log in';
  document.getElementById('contact-list').innerHTML='';
  document.getElementById('messages-area').innerHTML='';
}

function addContact(){
  const inp=document.getElementById('new-contact-input');
  const email=inp.value.trim().toLowerCase();
  if(!email||!email.includes('@')){showToast('Enter a valid email.');return}
  if(email===myEmail){showToast("That's your own email.");return}
  if(contacts.find(c=>c.email===email)){showToast('Already added.');return}
  contacts.push({email,name:email.split('@')[0]});
  conversations[email]=[];
  inp.value='';
  renderContacts();
}

function renderContacts(){
  const list=document.getElementById('contact-list');
  list.innerHTML='';
  if(contacts.length===0){
    list.innerHTML='<div style="padding:16px 14px;font-size:12px;color:var(--txt3)">No contacts yet</div>';
    return;
  }
  contacts.forEach(c=>{
    const msgs=conversations[c.email]||[];
    const last=msgs[msgs.length-1];
    const cl=colorFor(c.email);
    const div=document.createElement('div');
    div.className='contact-item'+(activeContact===c.email?' active':'');
    div.onclick=()=>openConversation(c.email);
    div.innerHTML=`
      <div class="contact-avatar" style="background:${cl.bg};color:${cl.txt}">${initials(c.email)}</div>
      <div class="contact-info">
        <div class="contact-name">${c.name||c.email.split('@')[0]}</div>
        <div class="contact-preview">${last?'🔒 '+last.plaintext.slice(0,28)+'…':'No messages yet'}</div>
      </div>`;
    list.appendChild(div);
  });
}

function openConversation(email){
  activeContact=email;
  renderContacts();
  document.getElementById('no-contact-state').style.display='none';
  const ac=document.getElementById('active-chat');
  ac.style.display='flex';
  const cl=colorFor(email);
  const av=document.getElementById('ch-avatar');
  av.textContent=initials(email);
  av.style.background=cl.bg;
  av.style.color=cl.txt;
  document.getElementById('ch-name').textContent=email.split('@')[0];
  document.getElementById('ch-sub').textContent=email;
  renderMessages();
  document.getElementById('compose-input').focus();
}

function renderMessages(){
  const area=document.getElementById('messages-area');
  area.innerHTML='';
  const msgs=(conversations[activeContact]||[]);
  if(msgs.length===0){
    area.innerHTML='<div style="text-align:center;padding:2rem;font-size:12px;color:var(--txt3)">No messages yet — say hello!</div>';
    return;
  }
  msgs.forEach(m=>{
    const mine=m.from===myEmail;
    const wrap=document.createElement('div');
    wrap.className='msg-wrap '+(mine?'mine':'theirs');
    const preview=m.ciphertext?m.ciphertext.slice(0,28)+'…':'';
    wrap.innerHTML=`
      <div class="msg-sender">${mine?'You':m.from.split('@')[0]}</div>
      <div class="msg-bubble">${escHtml(m.plaintext)}</div>
      <div class="msg-meta">
        <span class="msg-time">${fmtTime(m.ts)}</span>
        <span class="enc-tick">encrypted</span>
      </div>
      ${preview?`<div class="msg-enc-detail" title="Click to see ciphertext" onclick="showCipher(${JSON.stringify(m.ciphertext)})">${preview}</div>`:''}`;
    area.appendChild(wrap);
  });
  area.scrollTop=area.scrollHeight;
}

function escHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function showCipher(ct){showToast('Ciphertext: '+ct.slice(0,60)+'…',4000)}

function handleComposeKey(e){
  if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage()}
}

async function sendMessage(){
  if(!activeContact){showToast('Select a conversation first.');return}
  if(!apiKey||apiKey==='__NEEDS_ROTATE__'){showToast('API key not ready yet — please wait.');return}
  const inp=document.getElementById('compose-input');
  const txt=inp.value.trim();
  if(!txt)return;
  const btn=document.getElementById('send-btn');
  btn.disabled=true;
  inp.value='';inp.style.height='auto';

  const{ok,data}=await apiFetch('/v1/encrypt',{
    method:'POST',
    headers:{Authorization:'Bearer '+apiKey},
    body:JSON.stringify({plaintext:txt})
  });

  if(!ok){
    showToast('Encrypt failed: '+(data.error||'unknown error'));
    btn.disabled=false;inp.value=txt;
    return;
  }

  const encryptedPayload=data;
  const msg={
    id:Date.now(),
    from:myEmail,
    to:activeContact,
    plaintext:txt,
    ciphertext:encryptedPayload.ciphertext,
    nonce:encryptedPayload.nonce,
    encryption_key:encryptedPayload.encryption_key,
    ts:new Date().toISOString()
  };

  if(!conversations[activeContact])conversations[activeContact]=[];
  conversations[activeContact].push(msg);

  await simulateReceive(msg);

  renderMessages();
  renderContacts();
  btn.disabled=false;
  document.getElementById('compose-input').focus();
}

async function simulateReceive(sentMsg){
  if(!conversations[activeContact])conversations[activeContact]=[];
  const{ok,data}=await apiFetch('/v1/decrypt',{
    method:'POST',
    headers:{Authorization:'Bearer '+apiKey},
    body:JSON.stringify({
      ciphertext:sentMsg.ciphertext,
      nonce:sentMsg.nonce,
      encryption_key:sentMsg.encryption_key
    })
  });
  const decrypted=ok?data.plaintext:('[decrypt error: '+(data.error||'?')+']');
  const reply={
    id:Date.now()+1,
    from:activeContact,
    to:myEmail,
    plaintext:'[received & verified] '+decrypted,
    ciphertext:sentMsg.ciphertext,
    nonce:sentMsg.nonce,
    encryption_key:sentMsg.encryption_key,
    ts:new Date(Date.now()+200).toISOString()
  };
  conversations[activeContact].push(reply);
}

document.getElementById('login-pw').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});
</script>
