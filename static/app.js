// ===============================
// FINAL WORKING E2EE app.js
// ===============================

window.addEventListener("load", async () => {

  // ---- HARD SAFETY CHECK ----
  if (!window.sodium) {
    alert("libsodium not loaded. Check public/libsodium.js");
    return;
  }

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

  // DOM
  const userIdInput = document.getElementById("userId");
  const roomInput = document.getElementById("conversationId");
  const connectBtn = document.getElementById("connectBtn");
  const joinBtn = document.getElementById("joinBtn");
  const sendBtn = document.getElementById("sendBtn");
  const msgInput = document.getElementById("msgInput");
  const chat = document.getElementById("chat");
  const status = document.getElementById("status");

  let ws = null;
  let roomKey = null;

  function log(msg, cls="") {
    const d = document.createElement("div");
    d.className = cls;
    d.textContent = msg;
    chat.appendChild(d);
    chat.scrollTop = chat.scrollHeight;
  }

  function wsUrl() {
    return (location.protocol === "https:" ? "wss" : "ws")
      + "://" + location.host + "/ws";
  }

  function loadRoomKey(room) {
    const k = localStorage.getItem("roomkey_" + room);
    if (k) return from_base64(k);

    const key = randombytes_buf(32);
    localStorage.setItem("roomkey_" + room, to_base64(key));
    return key;
  }

  connectBtn.onclick = () => {
    const user = userIdInput.value.trim();
    if (!user) return alert("Enter user");

    ws = new WebSocket(wsUrl());
    status.textContent = "connecting...";

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "auth", userId: user }));
      status.textContent = "connected";
      log("Connected as " + user, "meta");
    };

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);

      if (msg.type === "message") {
        try {
          const text = crypto_secretbox_open_easy(
            from_base64(msg.ciphertext),
            from_base64(msg.nonce),
            roomKey
          );
          log(msg.from + ": " + new TextDecoder().decode(text), "peer");
        } catch {
          log("[decrypt failed] " + msg.ciphertext, "meta");
        }
      }
    };

    ws.onerror = () => status.textContent = "error";
    ws.onclose = () => status.textContent = "disconnected";
  };

  joinBtn.onclick = () => {
    const room = roomInput.value.trim();
    if (!room) return alert("Enter room");

    roomKey = loadRoomKey(room);
    log("Joined room: " + room, "meta");

    ws.send(JSON.stringify({ type: "join", roomId: room }));
  };

  sendBtn.onclick = () => {
    if (!roomKey) return alert("Join room first");

    const text = msgInput.value;
    if (!text) return;

    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);
    const cipher = crypto_secretbox_easy(
      new TextEncoder().encode(text),
      nonce,
      roomKey
    );

    ws.send(JSON.stringify({
      type: "send_message",
      roomId: roomInput.value.trim(),
      ciphertext: to_base64(cipher),
      nonce: to_base64(nonce)
    }));

    log("me: " + text, "me");
    msgInput.value = "";
  };

});
