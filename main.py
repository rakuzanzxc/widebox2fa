import asyncio
import html
import json
import os
import secrets
import sqlite3
import time
import urllib.parse
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

BOT_TOKEN = os.environ["BOT_TOKEN"]
BOT_USERNAME = os.environ["BOT_USERNAME"].lstrip("@")
CHANNEL_ID = os.environ["CHANNEL_ID"]
CHANNEL_URL = os.environ["CHANNEL_URL"]
SERVICE_API_KEY = os.environ["SERVICE_API_KEY"]
DATABASE_PATH = os.getenv("DATABASE_PATH", "./widebox2fa.db")

TG = f"https://api.telegram.org/bot{BOT_TOKEN}"
LINK_TTL = 300
LOGIN_TTL = 60
UNLINK_TTL = 300

db = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row

def init_db():
    db.executescript("""
    PRAGMA journal_mode=WAL;

    CREATE TABLE IF NOT EXISTS linked_accounts (
        minecraft_uuid TEXT PRIMARY KEY,
        minecraft_name TEXT NOT NULL,
        telegram_id INTEGER NOT NULL UNIQUE,
        telegram_username TEXT,
        linked_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS link_tokens (
        token TEXT PRIMARY KEY,
        minecraft_uuid TEXT NOT NULL,
        minecraft_name TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS login_sessions (
        session_id TEXT PRIMARY KEY,
        minecraft_uuid TEXT NOT NULL,
        telegram_id INTEGER NOT NULL,
        minecraft_name TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS unlink_sessions (
        session_id TEXT PRIMARY KEY,
        minecraft_uuid TEXT NOT NULL,
        telegram_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_login_uuid ON login_sessions(minecraft_uuid);
    CREATE INDEX IF NOT EXISTS idx_link_uuid ON link_tokens(minecraft_uuid);
    """)
    db.commit()

def now() -> int:
    return int(time.time())

def auth(x_api_key: Optional[str]):
    if not x_api_key or not secrets.compare_digest(x_api_key, SERVICE_API_KEY):
        raise HTTPException(401, "invalid api key")

async def tg(method: str, payload: dict):
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(f"{TG}/{method}", json=payload)
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError(f"Telegram {method}: {data}")
        return data["result"]

async def send(chat_id: int, text: str, keyboard=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    return await tg("sendMessage", payload)

async def answer_callback(callback_id: str, text: str, alert=False):
    try:
        await tg("answerCallbackQuery", {
            "callback_query_id": callback_id,
            "text": text,
            "show_alert": alert,
        })
    except Exception:
        pass

async def is_subscribed(user_id: int) -> bool:
    try:
        member = await tg("getChatMember", {
            "chat_id": CHANNEL_ID,
            "user_id": user_id
        })
        return member.get("status") in {"creator", "administrator", "member"}
    except Exception:
        return False

def get_link_token(token: str):
    row = db.execute(
        "SELECT * FROM link_tokens WHERE token=?",
        (token,)
    ).fetchone()
    if not row:
        return None
    if row["used_at"] is not None or row["expires_at"] < now():
        return None
    return row

async def finish_link(token: str, user: dict, chat_id: int):
    row = get_link_token(token)
    if not row:
        await send(chat_id, "❌ Ссылка привязки недействительна или уже использована.")
        return

    user_id = int(user["id"])
    username = user.get("username")

    existing_tg = db.execute(
        "SELECT minecraft_name FROM linked_accounts WHERE telegram_id=?",
        (user_id,)
    ).fetchone()
    if existing_tg:
        await send(
            chat_id,
            "❌ Этот Telegram уже привязан к Minecraft-аккаунту "
            f"<b>{html.escape(existing_tg['minecraft_name'])}</b>."
        )
        return

    existing_mc = db.execute(
        "SELECT telegram_id FROM linked_accounts WHERE minecraft_uuid=?",
        (row["minecraft_uuid"],)
    ).fetchone()
    if existing_mc:
        await send(chat_id, "❌ Этот Minecraft-аккаунт уже имеет привязанный Telegram.")
        return

    try:
        db.execute(
            """INSERT INTO linked_accounts
               (minecraft_uuid, minecraft_name, telegram_id, telegram_username, linked_at)
               VALUES (?, ?, ?, ?, ?)""",
            (row["minecraft_uuid"], row["minecraft_name"], user_id, username, now())
        )
        db.execute(
            "UPDATE link_tokens SET used_at=? WHERE token=? AND used_at IS NULL",
            (now(), token)
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        await send(chat_id, "❌ Этот Telegram или Minecraft-аккаунт уже привязан.")
        return

    await send(
        chat_id,
        "✅ <b>2FA подключена</b>\n\n"
        f"Minecraft: <code>{html.escape(row['minecraft_name'])}</code>\n"
        "Привязка действует бессрочно, пока ты сам её не отключишь."
    )

async def start_link_flow(message: dict, token: str):
    chat_id = message["chat"]["id"]
    user = message["from"]
    row = get_link_token(token)
    if not row:
        await send(chat_id, "❌ Ссылка привязки недействительна или уже использована.")
        return

    if not await is_subscribed(int(user["id"])):
        keyboard = [
            [{"text": "📢 Подписаться", "url": CHANNEL_URL}],
            [{"text": "✅ Проверить подписку", "callback_data": f"sub:{token}"}]
        ]
        await send(
            chat_id,
            "🔐 <b>Привязка WIDEBOX</b>\n\n"
            "Для использования 2FA необходимо подписаться на наш Telegram-канал.",
            keyboard
        )
        return

    await finish_link(token, user, chat_id)

async def handle_message(message: dict):
    text = message.get("text", "")
    if not text.startswith("/start"):
        return
    parts = text.split(maxsplit=1)
    if len(parts) != 2:
        await send(message["chat"]["id"], "Используй ссылку, которую сервер выдаёт командой /2fa.")
        return
    await start_link_flow(message, parts[1].strip())

async def handle_callback(cb: dict):
    data = cb.get("data", "")
    user = cb["from"]
    chat_id = cb["message"]["chat"]["id"]
    callback_id = cb["id"]

    if data.startswith("sub:"):
        token = data[4:]
        if not await is_subscribed(int(user["id"])):
            await answer_callback(callback_id, "Ты ещё не подписан на канал.", True)
            return
        await answer_callback(callback_id, "Подписка подтверждена.")
        await finish_link(token, user, chat_id)
        return

    if data.startswith("login:"):
        parts = data.split(":")
        if len(parts) != 3:
            return
        action, session_id = parts[1], parts[2]
        row = db.execute(
            "SELECT * FROM login_sessions WHERE session_id=?",
            (session_id,)
        ).fetchone()
        if not row:
            await answer_callback(callback_id, "Запрос уже недействителен.", True)
            return
        if int(row["telegram_id"]) != int(user["id"]):
            await answer_callback(callback_id, "Это не твой запрос.", True)
            return
        if row["status"] != "pending" or row["expires_at"] < now():
            if row["status"] == "pending":
                db.execute("UPDATE login_sessions SET status='expired' WHERE session_id=?", (session_id,))
                db.commit()
            await answer_callback(callback_id, "Запрос уже истёк.", True)
            return

        new_status = "approved" if action == "yes" else "denied"
        db.execute(
            "UPDATE login_sessions SET status=? WHERE session_id=? AND status='pending'",
            (new_status, session_id)
        )
        db.commit()
        await answer_callback(callback_id, "Вход разрешён." if new_status == "approved" else "Вход отклонён.")
        await send(
            chat_id,
            "✅ Вход разрешён." if new_status == "approved"
            else "⛔ Вход отклонён. Игрок будет отключён от сервера."
        )
        return

    if data.startswith("unlink:"):
        parts = data.split(":")
        if len(parts) != 3:
            return
        action, session_id = parts[1], parts[2]
        row = db.execute(
            "SELECT * FROM unlink_sessions WHERE session_id=?",
            (session_id,)
        ).fetchone()
        if not row or row["status"] != "pending" or row["expires_at"] < now():
            await answer_callback(callback_id, "Запрос уже недействителен.", True)
            return
        if int(row["telegram_id"]) != int(user["id"]):
            await answer_callback(callback_id, "Это не твой запрос.", True)
            return

        if action == "yes":
            db.execute(
                "DELETE FROM linked_accounts WHERE minecraft_uuid=? AND telegram_id=?",
                (row["minecraft_uuid"], row["telegram_id"])
            )
            db.execute(
                "UPDATE unlink_sessions SET status='approved' WHERE session_id=?",
                (session_id,)
            )
            db.commit()
            await answer_callback(callback_id, "2FA отключена.")
            await send(chat_id, "✅ Telegram успешно отвязан от Minecraft-аккаунта.")
        else:
            db.execute(
                "UPDATE unlink_sessions SET status='denied' WHERE session_id=?",
                (session_id,)
            )
            db.commit()
            await answer_callback(callback_id, "Отвязка отменена.")
            await send(chat_id, "✅ Отвязка отменена. 2FA остаётся включённой.")
        return

async def telegram_polling():
    offset = 0
    while True:
        try:
            async with httpx.AsyncClient(timeout=40) as client:
                r = await client.get(
                    f"{TG}/getUpdates",
                    params={
                        "timeout": 30,
                        "offset": offset,
                        "allowed_updates": json.dumps(["message", "callback_query"])
                    }
                )
                data = r.json()
                if not data.get("ok"):
                    await asyncio.sleep(3)
                    continue

                for update in data["result"]:
                    offset = update["update_id"] + 1
                    try:
                        if "message" in update:
                            await handle_message(update["message"])
                        elif "callback_query" in update:
                            await handle_callback(update["callback_query"])
                    except Exception as exc:
                        print("Update error:", repr(exc))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print("Polling error:", repr(exc))
            await asyncio.sleep(3)

def expire_sessions():
    t = now()
    db.execute(
        "UPDATE login_sessions SET status='expired' WHERE status='pending' AND expires_at < ?",
        (t,)
    )
    db.execute(
        "UPDATE unlink_sessions SET status='expired' WHERE status='pending' AND expires_at < ?",
        (t,)
    )
    db.commit()

async def janitor():
    while True:
        try:
            expire_sessions()
            cutoff = now() - 86400
            db.execute("DELETE FROM link_tokens WHERE expires_at < ?", (cutoff,))
            db.execute("DELETE FROM login_sessions WHERE created_at < ?", (cutoff,))
            db.execute("DELETE FROM unlink_sessions WHERE created_at < ?", (cutoff,))
            db.commit()
        except Exception as exc:
            print("Janitor error:", repr(exc))
        await asyncio.sleep(30)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    poll_task = asyncio.create_task(telegram_polling())
    janitor_task = asyncio.create_task(janitor())
    yield
    poll_task.cancel()
    janitor_task.cancel()

app = FastAPI(title="WideBox 2FA", docs_url=None, redoc_url=None, lifespan=lifespan)

class McIdentity(BaseModel):
    minecraft_uuid: str
    minecraft_name: str

class UnlinkRequest(BaseModel):
    minecraft_uuid: str

@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/v1/account/{minecraft_uuid}")
async def account(minecraft_uuid: str, x_api_key: Optional[str] = Header(None)):
    auth(x_api_key)
    row = db.execute(
        "SELECT minecraft_name, telegram_username, linked_at FROM linked_accounts WHERE minecraft_uuid=?",
        (minecraft_uuid,)
    ).fetchone()
    if not row:
        return {"linked": False}
    return {
        "linked": True,
        "minecraft_name": row["minecraft_name"],
        "telegram_username": row["telegram_username"],
        "linked_at": row["linked_at"]
    }

@app.post("/v1/link/request")
async def link_request(body: McIdentity, x_api_key: Optional[str] = Header(None)):
    auth(x_api_key)

    linked = db.execute(
        "SELECT 1 FROM linked_accounts WHERE minecraft_uuid=?",
        (body.minecraft_uuid,)
    ).fetchone()
    if linked:
        raise HTTPException(409, "minecraft account already linked")

    # Invalidate every older unused token for this UUID.
    db.execute(
        "UPDATE link_tokens SET used_at=? WHERE minecraft_uuid=? AND used_at IS NULL",
        (now(), body.minecraft_uuid)
    )

    token = secrets.token_urlsafe(24)
    created = now()
    db.execute(
        """INSERT INTO link_tokens
           (token, minecraft_uuid, minecraft_name, created_at, expires_at, used_at)
           VALUES (?, ?, ?, ?, ?, NULL)""",
        (token, body.minecraft_uuid, body.minecraft_name, created, created + LINK_TTL)
    )
    db.commit()

    deep_link = f"https://t.me/{BOT_USERNAME}?start={urllib.parse.quote(token)}"
    return {"token": token, "deep_link": deep_link, "expires_in": LINK_TTL}

@app.post("/v1/login/request")
async def login_request(body: McIdentity, x_api_key: Optional[str] = Header(None)):
    auth(x_api_key)
    row = db.execute(
        "SELECT telegram_id FROM linked_accounts WHERE minecraft_uuid=?",
        (body.minecraft_uuid,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "2fa not linked")

    # A reconnect invalidates all older pending approvals.
    db.execute(
        "UPDATE login_sessions SET status='cancelled' WHERE minecraft_uuid=? AND status='pending'",
        (body.minecraft_uuid,)
    )

    session_id = secrets.token_urlsafe(18)
    created = now()
    db.execute(
        """INSERT INTO login_sessions
           (session_id, minecraft_uuid, telegram_id, minecraft_name, status, created_at, expires_at)
           VALUES (?, ?, ?, ?, 'pending', ?, ?)""",
        (session_id, body.minecraft_uuid, int(row["telegram_id"]), body.minecraft_name,
         created, created + LOGIN_TTL)
    )
    db.commit()

    keyboard = [[
        {"text": "✅ Это я", "callback_data": f"login:yes:{session_id}"},
        {"text": "❌ Это не я", "callback_data": f"login:no:{session_id}"}
    ]]
    await send(
        int(row["telegram_id"]),
        "🔐 <b>WIDEBOX • ПОДТВЕРЖДЕНИЕ ВХОДА</b>\n\n"
        f"Аккаунт: <code>{html.escape(body.minecraft_name)}</code>\n"
        "Кто-то пытается войти в аккаунт.\n\n"
        "Запрос действует 60 секунд.",
        keyboard
    )
    return {"session_id": session_id, "expires_in": LOGIN_TTL}

@app.get("/v1/login/{session_id}")
async def login_status(session_id: str, x_api_key: Optional[str] = Header(None)):
    auth(x_api_key)
    row = db.execute(
        "SELECT status, expires_at FROM login_sessions WHERE session_id=?",
        (session_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "session not found")

    status = row["status"]
    if status == "pending" and row["expires_at"] < now():
        status = "expired"
        db.execute(
            "UPDATE login_sessions SET status='expired' WHERE session_id=? AND status='pending'",
            (session_id,)
        )
        db.commit()
    return {"status": status}

@app.post("/v1/login/{session_id}/cancel")
async def login_cancel(session_id: str, x_api_key: Optional[str] = Header(None)):
    auth(x_api_key)
    db.execute(
        "UPDATE login_sessions SET status='cancelled' WHERE session_id=? AND status='pending'",
        (session_id,)
    )
    db.commit()
    return {"ok": True}

@app.post("/v1/unlink/request")
async def unlink_request(body: UnlinkRequest, x_api_key: Optional[str] = Header(None)):
    auth(x_api_key)
    row = db.execute(
        "SELECT telegram_id, minecraft_name FROM linked_accounts WHERE minecraft_uuid=?",
        (body.minecraft_uuid,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "2fa not linked")

    db.execute(
        "UPDATE unlink_sessions SET status='cancelled' WHERE minecraft_uuid=? AND status='pending'",
        (body.minecraft_uuid,)
    )

    session_id = secrets.token_urlsafe(18)
    created = now()
    db.execute(
        """INSERT INTO unlink_sessions
           (session_id, minecraft_uuid, telegram_id, status, created_at, expires_at)
           VALUES (?, ?, ?, 'pending', ?, ?)""",
        (session_id, body.minecraft_uuid, int(row["telegram_id"]), created, created + UNLINK_TTL)
    )
    db.commit()

    keyboard = [[
        {"text": "✅ Отвязать", "callback_data": f"unlink:yes:{session_id}"},
        {"text": "❌ Отмена", "callback_data": f"unlink:no:{session_id}"}
    ]]
    await send(
        int(row["telegram_id"]),
        "⚠️ <b>Отключение WIDEBOX 2FA</b>\n\n"
        f"Аккаунт: <code>{html.escape(row['minecraft_name'])}</code>\n"
        "Подтвердить отвязку Telegram?",
        keyboard
    )
    return {"session_id": session_id, "expires_in": UNLINK_TTL}
