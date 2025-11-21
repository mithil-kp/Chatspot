# main.py
import os
import json
import uuid
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from typing import Dict, List, Set
from pathlib import Path

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)  # ensure folder exists (should contain frontend files)

app = FastAPI(title="Chat Prototype (Python Backend)")

# Serve static frontend files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# In-memory stores (demo only)
conversations: Dict[str, List[dict]] = {}  # conv_id -> list of envelopes
subscriptions: Dict[str, Set[WebSocket]] = {}  # conv_id -> websockets set
connections: Set[WebSocket] = set()  # all websockets


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Accepts an encrypted blob and saves it. Returns a URL to download the blob.
    Frontend is expected to encrypt files client-side before uploading.
    """
    # generate unique filename
    filename = f"{uuid.uuid4().hex}-{file.filename}"
    out_path = UPLOAD_DIR / filename
    with out_path.open("wb") as f:
        content = await file.read()
        f.write(content)
    # return path relative to server
    url = f"/uploads/{filename}"
    return {"url": url}


@app.get("/uploads/{fn}")
async def serve_upload(fn: str):
    path = UPLOAD_DIR / fn
    if not path.exists():
        return {"error": "not found"}
    return FileResponse(path)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """
    Expected WebSocket messages are JSON objects:
    - identify: { action: "identify", userId: "user-1" }
    - subscribe: { action: "subscribe", conversationId: "room1" }
    - message: { action: "message", envelope: { conversationId, senderId, iv, ciphertext, ... } }
    The server stores envelopes (opaque) and fans out to subscribers of that conversation.
    """
    await ws.accept()
    connections.add(ws)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                # ignore malformed
                continue

            action = msg.get("action")
            if action == "identify":
                # optional: we could store mapping WS->userId, but not required for demo
                ws._user_id = msg.get("userId")
                await ws.send_text(json.dumps({"action": "identified", "userId": ws._user_id}))
                continue

            if action == "subscribe":
                conv = msg.get("conversationId")
                if conv is None:
                    continue
                if conv not in subscriptions:
                    subscriptions[conv] = set()
                subscriptions[conv].add(ws)
                # send history
                history = conversations.get(conv, [])
                await ws.send_text(json.dumps({"action": "history", "conversationId": conv, "history": history}))
                continue

            if action == "message":
                envelope = msg.get("envelope")
                if not envelope:
                    continue
                conv = envelope.get("conversationId")
                if not conv:
                    continue
                # store envelope
                conversations.setdefault(conv, []).append(envelope)
                # fan-out
                subs = subscriptions.get(conv, set()).copy()
                payload = json.dumps({"action": "message", "envelope": envelope})
                to_remove = []
                for s in subs:
                    try:
                        await s.send_text(payload)
                    except Exception:
                        # connection likely dead; mark for removal
                        to_remove.append(s)
                for s in to_remove:
                    subscriptions[conv].discard(s)
                continue

            # unknown action -> ignore
    except WebSocketDisconnect:
        # cleanup: remove from any subscriptions
        connections.discard(ws)
        for conv_set in subscriptions.values():
            conv_set.discard(ws)
    finally:
        # best effort cleanup
        connections.discard(ws)
        for conv_set in subscriptions.values():
            conv_set.discard(ws)
