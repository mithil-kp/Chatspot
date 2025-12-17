# main.py
import json
from pathlib import Path
from typing import Dict, List, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse

app = FastAPI(title="Chat Prototype (Python Backend)")


BASE_DIR = Path(__file__).parent.resolve()
STATIC_DIR = BASE_DIR / "static"
if not STATIC_DIR.exists():
   
    STATIC_DIR = BASE_DIR


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


conversations: Dict[str, List[dict]] = {}
subscriptions: Dict[str, Set[WebSocket]] = {}
connections: Set[WebSocket] = set()


@app.get("/")
async def index():
    """
    Serve index.html from STATIC_DIR (preferred ./static/index.html).
    If missing, return a helpful error message instead of a 500.
    """
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return PlainTextResponse(
            "index.html not found on server. Expected at: " + str(index_path),
            status_code=500,
        )
    return FileResponse(index_path, media_type="text/html")


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
                # ignore malformed messages
                continue

            action = msg.get("action")
            if action == "identify":
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
                # store envelope (opaque payload)
                conversations.setdefault(conv, []).append(envelope)
                # fan-out to subscribers of conversation
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
