// ===============================
// ChatSpot – FINAL Web Crypto E2EE
// ===============================

// --- Encoding helpers ---
const enc = new TextEncoder();
const dec = new TextDecoder();

// --- State ---
let ws = null;
let roomKey = null;
let joined = false;

// --- DOM ---
const userIdInput = document.getElementById("userId");
const connectBtn = document.getElementById("connectBtn");
const joinBtn = document.getElementById("joinBtn");
const sendBtn = document.getElementById("sendBtn");
const msgInput = document.getElementById("msgInput");
const chat = document.getElementById("chat");
const statusEl = document.getElementById("status");
const roomInput = document.getElementById("conversationId");

// --- UI helpers ---
function log(text, me = false) {
  const div = document.createElement("div");
  div.className = "msg" + (me ? " me" : "");
  div.innerHTML = `<pre>${text}</pre>`;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

// --- WebSocket URL ---
function wsUrl() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/ws`;
}

// --- Base64 helpers ---
function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// --- Room key handling (persistent) ---
async function loadOrCreateRoomKey(room) {
  const saved = localStorage.getItem("roomkey_" + room);
  if (saved) {
    return crypto.subtle.importKey(
      "raw",
      b64ToBuf(saved),
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );
  }

  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const raw = await crypto.subtle.exportKey("raw", key);
  localStorage.setItem("roomkey_" + room, bufToB64(raw));
  return key;
}

// --- SAFE DECRYPT (never crashes) ---
async function safeDecrypt(cipherB64, ivB64) {
  if (!roomKey) {
    console.warn("Decrypt skipped: roomKey not ready");
    return "[key not ready]";
  }

  try {
    const iv = b64ToBuf(ivB64);
    const data = b64ToBuf(cipherB64);

    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      roomKey,
      data
    );
    return dec.decode(plain);
  } catch (err) {
    console.error("Decrypt failed:", err);
    return "[decrypt failed]";
  }
}

// ===============================
// CONNECT
// ===============================
connectBtn.onclick = () => {
  const user = userIdInput.value.trim();
  if (!user) return alert("Enter username");

  ws = new WebSocket(wsUrl());
  statusEl.textContent = "connecting…";

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", userId: user }));
    statusEl.textContent = "connected";
    log("Connected as " + user);
  };

  ws.onmessage = async (e) => {
    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }

    if (msg.type === "message") {
      const text = await safeDecrypt(msg.cipher, msg.iv);
      log(msg.from + ": " + text);
    }
  };

  ws.onerror = () => {
    statusEl.textContent = "error";
  };

  ws.onclose = () => {
    statusEl.textContent = "disconnected";
    joined = false;
    roomKey = null;
  };
};

// ===============================
// JOIN ROOM
// ===============================
joinBtn.onclick = async () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return alert("Connect first");
  }

  const room = roomInput.value.trim();
  if (!room) return alert("Enter conversation ID");

  roomKey = await loadOrCreateRoomKey(room);
  joined = true;

  ws.send(JSON.stringify({ type: "join", roomId: room }));
  log("Joined room: " + room);
};

// ===============================
// SEND MESSAGE
// ===============================
sendBtn.onclick = async () => {
  if (!joined) return alert("Join room first");
  if (!msgInput.value) return;

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    roomKey,
    enc.encode(msgInput.value)
  );

  ws.send(JSON.stringify({
    type: "send_message",
    roomId: roomInput.value,
    cipher: bufToB64(cipher),
    iv: bufToB64(iv)
  }));

  log("me: " + msgInput.value, true);
  msgInput.value = "";
};
