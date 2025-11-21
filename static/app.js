// static/app.js
// Vanilla JS frontend. Uses Web Crypto API for AES-GCM key per user.
// WebSocket connects to ws://<host>:8000/ws (uvicorn default port 8000)

const enc = new TextEncoder();
const dec = new TextDecoder();

const WS_PATH = (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/ws';
const uploadPath = (location.protocol === 'https:' ? 'https' : 'http') + '://' + location.host + '/upload';

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

async function encryptText(key, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = enc.encode(plain);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
  return { iv: bufToBase64(iv), ciphertext: bufToBase64(ct) };
}

async function decryptText(key, ivB64, ctB64) {
  const iv = new Uint8Array(base64ToBuf(ivB64));
  const ct = base64ToBuf(ctB64);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return dec.decode(ptBuf);
}

// Key management in localStorage:
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

// UI elements
const userInput = document.getElementById('userIdInput');
const saveUserBtn = document.getElementById('saveUserBtn');
const convInput = document.getElementById('convId');
const joinBtn = document.getElementById('joinBtn');
const messagesDiv = document.getElementById('messages');
const metaDiv = document.getElementById('meta');
const textInput = document.getElementById('text');
const sendBtn = document.getElementById('sendBtn');
const fileInput = document.getElementById('fileInput');

let ws = null;
let key = null;
let userId = localStorage.getItem('chat_user') || ('user-' + Math.floor(Math.random()*1000));
userInput.value = userId;
let convId = convInput.value || 'room1';

saveUserBtn.onclick = () => {
  userId = userInput.value || userId;
  localStorage.setItem('chat_user', userId);
  metaDiv.innerText = `User: ${userId} — Conversation: ${convId}`;
};

joinBtn.onclick = async () => {
  convId = convInput.value || convId;
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    await connectWs();
  }
  ws.send(JSON.stringify({ action: 'subscribe', conversationId: convId }));
  metaDiv.innerText = `User: ${userId} — Conversation: ${convId}`;
  messagesDiv.innerHTML = '';
};

async function connectWs() {
  ws = new WebSocket(WS_PATH);
  ws.addEventListener('open', () => {
    console.log('ws open');
    ws.send(JSON.stringify({ action: 'identify', userId }));
    ws.send(JSON.stringify({ action: 'subscribe', conversationId: convId }));
  });
  ws.addEventListener('message', async (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.action === 'identified') {
      console.log('identified', msg.userId);
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
  });
  ws.addEventListener('close', () => console.log('ws closed'));
}

async function handleIncomingEnvelope(env) {
  // env may be {conversationId, senderId, iv, ciphertext, kind?, meta?, timestamp}
  const el = document.createElement('div');
  el.className = 'msg';
  const header = document.createElement('div');
  header.className = 'sender';
  header.innerText = `${env.senderId} — ${new Date(env.timestamp || Date.now()).toLocaleString()}`;
  el.appendChild(header);

  if (env.kind === 'file') {
    // ciphertext holds the URL to encrypted blob
    const link = document.createElement('a');
    link.href = env.ciphertext;
    link.innerText = `Encrypted file: ${env.meta?.filename || 'file'}`;
    link.target = '_blank';
    el.appendChild(link);
    const ivLine = document.createElement('div');
    ivLine.className = 'iv';
    ivLine.innerText = `IV (b64): ${env.iv}`;
    el.appendChild(ivLine);
  } else {
    let text = env.ciphertext;
    try {
      text = await decryptText(key, env.iv, env.ciphertext);
    } catch (e) {
      text = '[decrypt failed]';
    }
    const pre = document.createElement('pre');
    pre.innerText = text;
    el.appendChild(pre);
  }
  messagesDiv.appendChild(el);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

sendBtn.onclick = async () => {
  const text = textInput.value.trim();
  if (!text) return;
  const { iv, ciphertext } = await encryptText(key, text);
  const envelope = { conversationId: convId, senderId: userId, iv, ciphertext, timestamp: Date.now() };
  ws.send(JSON.stringify({ action: 'message', envelope }));
  textInput.value = '';
};

fileInput.onchange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  // Read file and encrypt it with AES-GCM (same key)
  const ab = await file.arrayBuffer();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, ab);
  // Upload encrypted blob to server
  const blob = new Blob([new Uint8Array(ct)], { type: 'application/octet-stream' });
  const form = new FormData();
  // name it with .enc suffix so server saves original filename in stored name
  form.append('file', blob, file.name + '.enc');
  const r = await fetch(uploadPath, { method: 'POST', body: form });
  const body = await r.json();
  if (body.url) {
    // send envelope that points to encrypted file; include iv so recipients can decrypt
    const envelope = {
      conversationId: convId,
      senderId: userId,
      iv: bufToBase64(iv),
      ciphertext: body.url,
      meta: { filename: file.name, type: file.type },
      timestamp: Date.now(),
      kind: 'file'
    };
    ws.send(JSON.stringify({ action: 'message', envelope }));
  } else {
    alert('upload failed');
  }
};

// boot
(async () => {
  // key handling
  key = await loadKeyFromLocal();
  if (!key) {
    key = await generateKey();
    await saveKeyToLocal(key);
    console.log('generated new key');
  } else {
    console.log('loaded existing key');
  }
  // connect and subscribe
  await connectWs();
  ws.send(JSON.stringify({ action: 'identify', userId }));
  ws.send(JSON.stringify({ action: 'subscribe', conversationId: convId }));
  metaDiv.innerText = `User: ${userId} — Conversation: ${convId}`;
})();
