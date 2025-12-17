// ===============================
// Chatspot – Web Crypto E2EE
// ===============================

const enc = new TextEncoder();
const dec = new TextDecoder();

let ws = null;
let roomKey = null;

// ---------- DOM ----------
const userId = document.getElementById("userId");
const connectBtn = document.getElementById("connectBtn");
const joinBtn = document.getElementById("joinBtn");
const sendBtn = document.getElementById("sendBtn");
const msgInput = document.getElementById("msgInput");
const chat = document.getElementById("chat");
const statusEl = document.getElementById("status");
const roomInput = document.getElementById("conversationId");

// ---------- HELPERS ----------
function log(text, me=false) {
  const div = document.createElement("div");
  div.className = "msg" + (me ? " me" : "");
  div.innerHTML = `<pre>${text}</pre>`;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function wsUrl() {
  const p = location.protocol === "https:" ? "wss" : "ws";
  return `${p}://${location.host}/ws`;
}

// ---------- KEY HANDLING ----------
async function loadOrCreateRoomKey(room) {
  const saved = localStorage.getItem("roomkey_" + room);
  if (saved) {
    return crypto.subtle.importKey(
      "raw",
      Uint8Array.from(atob(saved), c => c.charCodeAt(0)),
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
  localStorage.setItem(
    "roomkey_" + room,
    btoa(String.fromCharCode(...new Uint8Array(raw)))
  );
  return key;
}

// ---------- CONNECT ----------
connectBtn.onclick = () => {
  if (!userId.value) return alert("Enter username");

  ws = new WebSocket(wsUrl());
  statusEl.textContent = "connecting…";

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", userId: userId.value }));
    statusEl.textContent = "connected";
    log("Connected as " + userId.value);
  };

  ws.onmessage = async (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === "message") {
      try {
        const iv = Uint8Array.from(atob(msg.iv), c => c.charCodeAt(0));
        const data = Uint8Array.from(atob(msg.cipher), c => c.charCodeAt(0));

        const plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          roomKey,
          data
        );
        log(msg.from + ": " + dec.decode(plain));
      } catch {
        log("[decrypt failed]");
      }
    }
  };

  ws.onclose = () => statusEl.textContent = "disconnected";
};

// ---------- JOIN ROOM ----------
joinBtn.onclick = async () => {
  const room = roomInput.value.trim();
  if (!room) return alert("Enter conversation ID");

  roomKey = await loadOrCreateRoomKey(room);
  ws.send(JSON.stringify({ type: "join", roomId: room }));
  log("Joined room: " + room);
};

// ---------- SEND ----------
sendBtn.onclick = async () => {
  if (!roomKey) return alert("Join room first");
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
    cipher: btoa(String.fromCharCode(...new Uint8Array(cipher))),
    iv: btoa(String.fromCharCode(...iv))
  }));

  log("me: " + msgInput.value, true);
  msgInput.value = "";
};
