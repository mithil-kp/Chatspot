// static/app.js
// Secure-ish chat client (no file uploads). Handles:
// - AES-GCM key management in localStorage
// - Robust WebSocket connect (waits until open)
// - Optimistic send + dedupe using message id
// - Defensive DOM handling (won't crash if elements missing)

const enc = new TextEncoder();
const dec = new TextDecoder();
const WS_PATH = (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/ws';

// --- Crypto helpers ---
async function generateKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function exportKeyRaw(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
}
async function importKeyRaw(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', true, ['encrypt', 'decrypt']);
}
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(s) {
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}
function isValidAesCryptoKey(k) {
  return !!k && typeof k === 'object' && k.type === 'secret' && k.algorithm && k.algorithm.name && k.algorithm.name.toUpperCase() === 'AES-GCM';
}

async function encryptText(key, plain) {
  if (!isValidAesCryptoKey(key)) throw new TypeError('encryptText: provided key is not a valid AES CryptoKey');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = enc.encode(plain);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
  return { iv: bufToBase64(iv), ciphertext: bufToBase64(ct) };
}

async function decryptText(key, ivB64, ctB64) {
  if (!isValidAesCryptoKey(key)) throw new TypeError('decryptText: provided key is not a valid AES CryptoKey');
  const iv = new Uint8Array(base64ToBuf(ivB64));
  const ct = base64ToBuf(ctB64);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return dec.decode(ptBuf);
}

async function saveKeyToLocal(key) {
  const raw = await exportKeyRaw(key);
  const b = btoa(String.fromCharCode(...raw));
  localStorage.setItem('chat_key', b);
}
async function loadKeyFromLocal() {
  const s = localStorage.getItem('chat_key');
  if (!s) return null;
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return importKeyRaw(arr.buffer);
}

// --- Small utilities ---
function safeLog(...args) { try { console.log(...args); } catch (e) {} }
function $(id) { return document.getElementById(id) || null; }
function makeId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.floor(Math.random()*1e9).toString(36)}`;
}

// --- DOM references (may be null if missing) ---
const userInput = $('userIdInput');
const saveUserBtn = $('saveUserBtn');
const convInput = $('convId');
const joinBtn = $('joinBtn');
const messagesDiv = $('messages');
const metaDiv = $('meta');
const textInput = $('text');
const sendBtn = $('sendBtn');

// Basic sanity: ensure the required elements are present (messages, text, sendBtn, meta)
if (!messagesDiv || !textInput || !sendBtn || !metaDiv) {
  const msg = 'Client missing required elements (messages, text, sendBtn, or meta). Check index.html IDs.';
  safeLog(msg);
  document.title = 'Client misconfigured';
  if (!metaDiv) {
    const b = document.createElement('div');
    b.style.background = '#ffdddd';
    b.style.color = '#900';
    b.style.padding = '8px';
    b.innerText = msg;
    document.body.insertBefore(b, document.body.firstChild);
  } else {
    metaDiv.innerText = msg;
  }
  // Stop initialization (avoid further null errors)
}

// --- Application state ---
let ws = null;
let key = null;
let userId = localStorage.getItem('chat_user') || ('user-' + Math.floor(Math.random()*1000));
if (userInput) userInput.value = userId;
let convId = (convInput && convInput.value) ? convInput.value : 'room1';

// dedupe support
const displayedMsgIds = new Set();

// --- UI helpers ---
function setMeta(text) { if (metaDiv) metaDiv.innerText = text; }

function appendMessageElement(env, decryptedText, isMe=false) {
  if (!messagesDiv) return;
  // record id if provided
  if (env && env.id) displayedMsgIds.add(env.id);

  const el = document.createElement('div');
  el.className = 'msg' + (isMe ? ' me' : '');
  const header = document.createElement('div');
  header.className = 'sender';
  header.innerText = `${env.senderId || 'unknown'} — ${new Date(env.timestamp || Date.now()).toLocaleString()}`;
  el.appendChild(header);

  const pre = document.createElement('pre');
  pre.innerText = decryptedText;
  el.appendChild(pre);

  messagesDiv.appendChild(el);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// --- Event wiring (defensive) ---
if (saveUserBtn) {
  saveUserBtn.addEventListener('click', () => {
    userId = (userInput && userInput.value) ? userInput.value : userId;
    localStorage.setItem('chat_user', userId);
    setMeta(`User: ${userId} — Conversation: ${convId}`);
  });
}

if (joinBtn) {
  joinBtn.addEventListener('click', async () => {
    convId = (convInput && convInput.value) ? convInput.value : convId;
    try {
      if (!ws || ws.readyState !== WebSocket.OPEN) await connectWs();
      // subscribe after open
      try { ws.send(JSON.stringify({ action: 'subscribe', conversationId: convId })); } catch(e){ safeLog('subscribe failed', e); }
      setMeta(`User: ${userId} — Conversation: ${convId}`);
      if (messagesDiv) messagesDiv.innerHTML = '';
    } catch (e) {
      safeLog('join failed', e);
      alert('Failed to join: ' + (e && e.message ? e.message : String(e)));
    }
  });
}

// --- Incoming envelope handling ---
async function handleIncomingEnvelope(env) {
  // dedupe: skip envelopes we already displayed
  if (env && env.id && displayedMsgIds.has(env.id)) return;

  let text = env.ciphertext || '';
  if (isValidAesCryptoKey(key)) {
    try {
      const t = await decryptText(key, env.iv, env.ciphertext);
      text = t;
    } catch (e) {
      safeLog('decrypt failed', e);
      text = `[decrypt failed — showing ciphertext]\n${env.ciphertext}`;
    }
  } else {
    text = `[no key loaded — showing ciphertext]\n${env.ciphertext}`;
  }
  const isMe = (env.senderId === userId);
  appendMessageElement(env, text, isMe);
}

// --- Send handler ---
if (sendBtn) {
  sendBtn.addEventListener('click', async () => {
    const text = textInput ? textInput.value.trim() : '';
    if (!text) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      alert('WebSocket not connected. Click Join or reload page.');
      return;
    }
    if (!isValidAesCryptoKey(key)) {
      alert('Encryption key missing or invalid. Reload the page.');
      return;
    }
    try {
      const { iv, ciphertext } = await encryptText(key, text);
      const msgId = makeId();
      const envelope = {
        id: msgId,
        conversationId: convId,
        senderId: userId,
        iv,
        ciphertext,
        timestamp: Date.now()
      };
      try {
        ws.send(JSON.stringify({ action: 'message', envelope }));
      } catch (e) {
        safeLog('ws send failed', e);
        alert('Send failed (ws). See console.');
        return;
      }
      // optimistic append (and record id to dedupe server echo)
      appendMessageElement(envelope, text, true);
      if (textInput) textInput.value = '';
    } catch (e) {
      safeLog('send error', e);
      alert('Send error: ' + (e && e.message ? e.message : String(e)));
    }
  });
}

// --- WebSocket connection (resolves when open) ---
function connectWs() {
  return new Promise((resolve, reject) => {
    try {
      ws = new WebSocket(WS_PATH);

      ws.addEventListener('open', () => {
        safeLog('ws open');
        try { ws.send(JSON.stringify({ action: 'identify', userId })); } catch(e){ safeLog('identify send failed', e); }
        try { ws.send(JSON.stringify({ action: 'subscribe', conversationId: convId })); } catch(e){ safeLog('subscribe send failed', e); }
        resolve();
      });

      ws.addEventListener('message', async (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.action === 'identified') {
            safeLog('identified', msg.userId);
            return;
          }
          if (msg.action === 'history') {
            const history = msg.history || [];
            for (const env of history) await handleIncomingEnvelope(env);
            return;
          }
          if (msg.action === 'message') {
            const env = msg.envelope;
            await handleIncomingEnvelope(env);
            return;
          }
        } catch (e) {
          safeLog('message handler failed', e);
        }
      });

      ws.addEventListener('close', (ev) => {
        safeLog('ws closed', ev);
      });

      ws.addEventListener('error', (err) => {
        safeLog('ws error', err);
      });
    } catch (e) {
      reject(e);
    }
  });
}

// --- Boot sequence ---
(async () => {
  try {
    key = await loadKeyFromLocal();
    if (!isValidAesCryptoKey(key)) {
      key = await generateKey();
      await saveKeyToLocal(key);
      safeLog('generated new key');
    } else {
      safeLog('loaded existing key');
    }

    await connectWs();
    setMeta(`User: ${userId} — Conversation: ${convId}`);
  } catch (e) {
    safeLog('boot error', e);
    setMeta('Error: ' + (e && e.message ? e.message : String(e)));
  }
})();
