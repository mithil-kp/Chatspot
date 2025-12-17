// ===============================
// Chat E2EE – FIXED app.js
// ===============================

// This file assumes libsodium is already loaded as window.sodium
// (via local libsodium.js or CDN loader)

(async () => {
  const sodium = window.sodium;
  await sodium.ready;

  const {
    randombytes_buf,
    crypto_secretbox_easy,
    crypto_secretbox_open_easy,
    crypto_secretbox_NONCEBYTES,
    to_base64,
    from_base64
  } = sodium;

  // ---------- DOM ----------
  const connectBtn = document.getElementById("connectBtn");
  const sendBtn = document.getElementById("sendBtn");
  const joinBtn = document.getElementById("joinBtn") || null;

  const userIdInput = document.getElementById("userId");
  const peerIdInput = document.getElementById("peerId") || null;
  const roomInput = document.getElementById("conversationId") || document.getElementById("roomId");

  const msgInput = document.getElementById("msgInput");
  const chatBox = document.getElementById("chat");
  const statusEl = document.getElementById("status");

  // ---------- STATE ----------
  let ws = null;
  let roomId = null;
  let roomKey = null; // Uint8Array(32)

  // ---------- HELPERS ----------
  function log(text, cls = "") {
    const div = document.createElement("div");
    div.className = "msg " + cls;
    div.textContent = text;
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
  }

  function setStatus(s) {
    if (statusEl) statusEl.textContent = s;
  }

  function wsUrl() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    return `${proto}://${location.host}/ws`;
  }

  // ---------- ROOM KEY (PERSISTENT) ----------
  function loadOrCreateRoomKey(roomId) {
    const k = localStorage.getItem("roomkey_" + roomId);
    if (k) return from_base64(k);

    const newKey = randombytes_buf(32);
    localStorage.setItem("roomkey_" + roomId, to_base64(newKey));
    return newKey;
  }

  // ---------- CONNECT ----------
  connectBtn.onclick = () => {
    const userId = userIdInput.value.trim();
    if (!userId) return alert("Enter user id");

    ws = new WebSocket(wsUrl());
    setStatus("connecting…");

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "auth", userId }));
      setStatus("connected");
      log(`Connected as ${userId}`, "me");
    };

    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }

      // -------- INCOMING MESSAGE --------
      if (msg.type === "message") {
        try {
          const ciphertext = from_base64(msg.ciphertext);
          const nonce = from_base64(msg.nonce);

          const plain = crypto_secretbox_open_easy(
            ciphertext,
            nonce,
            roomKey
          );

          const text = new TextDecoder().decode(plain);
          log(`${msg.from}: ${text}`, "peer");

        } catch (e) {
          log(`[decrypt failed — showing ciphertext]\n${msg.ciphertext}`, "meta");
        }
      }
    };

    ws.onclose = () => setStatus("disconnected");
    ws.onerror = () => setStatus("error");
  };

  // ---------- JOIN ROOM ----------
  if (joinBtn) {
    joinBtn.onclick = () => {
      roomId = roomInput.value.trim();
      if (!roomId) return alert("Enter conversation ID");

      roomKey = loadOrCreateRoomKey(roomId);
      log(`Joined room: ${roomId}`, "meta");

      ws.send(JSON.stringify({
        type: "join",
        roomId
      }));
    };
  }

  // ---------- SEND MESSAGE ----------
  sendBtn.onclick = () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return alert("Not connected");
    }
    if (!roomKey) return alert("Join a room first");

    const text = msgInput.value;
    if (!text) return;

    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);
    const plaintext = new TextEncoder().encode(text);

    const ciphertext = crypto_secretbox_easy(
      plaintext,
      nonce,
      roomKey
    );

    ws.send(JSON.stringify({
      type: "send_message",
      roomId,
      ciphertext: to_base64(ciphertext),
      nonce: to_base64(nonce)
    }));

    log(`me: ${text}`, "me");
    msgInput.value = "";
  };

})();
