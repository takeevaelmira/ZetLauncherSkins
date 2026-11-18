"""
ZetLauncher Skin Server: Yggdrasil-совместимый сервер скинов для authlib-injector + каталог скинов.

Переменные окружения (Railway -> Variables):
  DATA_DIR    папка для данных (по умолчанию ./data). На Railway подключите Volume и укажите /data,
              иначе скины и аккаунты пропадут при каждом деплое.
  PUBLIC_URL  необязательно: https://ваш-проект.up.railway.app (если не задан, берётся из запроса)
  ADMIN_KEY   необязательно: ключ для добавления скинов в каталог вручную
"""
import base64
import hashlib
import io
import json
import os
import re
import secrets
import time
import uuid
import urllib.parse
from pathlib import Path
from bs4 import BeautifulSoup
import random

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from PIL import Image

DATA = Path(os.environ.get("DATA_DIR", "data"))
SKINS = DATA / "skins"        # PNG по хэшу содержимого: <sha256>.png
PREVIEWS = DATA / "previews"  # картинки для карточек каталога
for d in (DATA, SKINS, PREVIEWS):
    d.mkdir(parents=True, exist_ok=True)

ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
MAX_PNG_BYTES = 256 * 1024
NICK_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")

app = FastAPI(title="ZetLauncher Skin Server")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ---------------- хранение ----------------

def _load(name: str) -> dict:
    f = DATA / name
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save(name: str, data: dict) -> None:
    tmp = DATA / (name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(DATA / name)


PLAYERS: dict = _load("players.json")   # ник(lower) -> {username, uuid, token_hash, slim, skin}
CATALOG: dict = _load("catalog.json")   # id(sha256) -> {id, name, slim, source, added}


# ---------------- ключ для подписи текстур ----------------

def _load_key() -> rsa.RSAPrivateKey:
    f = DATA / "key.pem"
    if f.exists():
        return serialization.load_pem_private_key(f.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    f.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return key


KEY = _load_key()
PUBLIC_PEM = KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def sign(value: str) -> str:
    sig = KEY.sign(value.encode("utf-8"), padding.PKCS1v15(), hashes.SHA1())
    return base64.b64encode(sig).decode()


# ---------------- утилиты ----------------

def offline_uuid(username: str) -> str:
    """Тот же UUID, что считает игра для офлайн-игрока (без дефисов)."""
    md5 = bytearray(hashlib.md5(f"OfflinePlayer:{username}".encode("utf-8")).digest())
    md5[6] = (md5[6] & 0x0F) | 0x30
    md5[8] = (md5[8] & 0x3F) | 0x80
    return md5.hex()


def public_base(request: Request) -> str:
    env = os.environ.get("PUBLIC_URL", "").rstrip("/")
    if env:
        return env
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
    return f"{proto}://{host}"


def validate_skin(data: bytes) -> Image.Image:
    if len(data) > MAX_PNG_BYTES:
        raise HTTPException(400, "file_too_big")
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        raise HTTPException(400, "bad_png")
    if img.format != "PNG":
        raise HTTPException(400, "bad_png")
    w, h = img.size
    if w not in (64, 128, 256) or h not in (w, w // 2):
        raise HTTPException(400, "bad_size")
    return img


def store_skin(data: bytes) -> str:
    """Сохраняет PNG по хэшу и возвращает хэш. Имя файла меняется вместе со скином, поэтому игра не держит старый кэш."""
    h = hashlib.sha256(data).hexdigest()
    f = SKINS / f"{h}.png"
    if not f.exists():
        f.write_bytes(data)
    return h


def check_token(username: str, token: str) -> dict:
    """Ник закрепляется за первым, кто его использовал; дальше нужен тот же токен."""
    if not re.fullmatch(r"[A-Za-z0-9_]{1,16}", username or ""):
        raise HTTPException(400, "bad_username")
    if len(token or "") < 16:
        raise HTTPException(401, "bad_token")
    th = hashlib.sha256(token.encode()).hexdigest()
    key = username.lower()
    p = PLAYERS.get(key)
    if p is None:
        p = {"username": username, "uuid": offline_uuid(username), "token_hash": th, "slim": False, "skin": None}
        PLAYERS[key] = p
    elif not secrets.compare_digest(p["token_hash"], th):
        raise HTTPException(403, "nick_taken")
    p["username"] = username
    p["uuid"] = offline_uuid(username)
    return p


# ---------------- превью для каталога ----------------

def render_preview(skin: Image.Image, slim: bool) -> Image.Image:
    """Вид спереди, 16x32 пикселя, потом увеличение."""
    skin = skin.convert("RGBA")
    s = skin.width // 64
    legacy = skin.height < skin.width

    def part(x, y, w, h, flip=False):
        im = skin.crop((x * s, y * s, (x + w) * s, (y + h) * s)).resize((w, h), Image.NEAREST)
        return im.transpose(Image.FLIP_LEFT_RIGHT) if flip else im

    canvas = Image.new("RGBA", (16, 32), (0, 0, 0, 0))

    def put(im, x, y):
        canvas.alpha_composite(im, (x, y))

    aw = 3 if slim else 4
    ax_r = 4 - aw          # правая рука (слева на картинке)
    ax_l = 12              # левая рука

    put(part(4, 20, 4, 12), 4, 20)                        # правая нога
    put(part(4, 20, 4, 12, True) if legacy else part(20, 52, 4, 12), 8, 20)
    put(part(20, 20, 8, 12), 4, 8)                        # тело
    put(part(44, 20, aw, 12), ax_r, 8)                    # правая рука
    put(part(44, 20, aw, 12, True) if legacy else part(36, 52, aw, 12), ax_l, 8)
    put(part(8, 8, 8, 8), 4, 0)                           # голова

    if not legacy:                                        # второй слой
        put(part(4, 36, 4, 12), 4, 20)
        put(part(4, 52, 4, 12), 8, 20)
        put(part(20, 36, 8, 12), 4, 8)
        put(part(44, 36, aw, 12), ax_r, 8)
        put(part(52, 52, aw, 12), ax_l, 8)
    put(part(40, 8, 8, 8), 4, 0)                          # шапка

    return canvas.resize((128, 256), Image.NEAREST)


def preview_file(skin_id: str, slim: bool) -> Path:
    out = PREVIEWS / f"{skin_id}.png"
    if not out.exists():
        src = SKINS / f"{skin_id}.png"
        if not src.exists():
            raise HTTPException(404, "not_found")
        render_preview(Image.open(src), slim).save(out)
    return out


def detect_slim(img: Image.Image) -> bool:
    """Тонкие руки: нужные области прозрачные (как в skinview3d)."""
    if img.height < img.width:
        return False
    img = img.convert("RGBA")
    s = img.width // 64
    for x, y, w, h in ((50, 16, 2, 4), (54, 20, 2, 12), (42, 48, 2, 4), (46, 52, 2, 12)):
        if any(a != 0 for a in img.crop((x * s, y * s, (x + w) * s, (y + h) * s)).getchannel("A").getdata()):
            return False
    return True


# ---------------- Yggdrasil (для authlib-injector) ----------------

ygg = APIRouter(prefix="/api/yggdrasil")


@ygg.get("")
@ygg.get("/")
async def ygg_meta(request: Request):
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost")).split(":")[0]
    return {
        "meta": {
            "serverName": "ZetLauncher Skins",
            "implementationName": "ZetYggdrasil",
            "implementationVersion": "2.0.0",
            "feature.no_mojang_namespace": True,
        },
        "skinDomains": [host, ".railway.app"],
        "signaturePublickey": PUBLIC_PEM,
    }


@ygg.get("/sessionserver/session/minecraft/profile/{player_uuid}")
async def ygg_profile(player_uuid: str, request: Request, unsigned: bool = True):
    clean = player_uuid.replace("-", "").lower()
    player = next((p for p in PLAYERS.values() if p["uuid"] == clean), None)
    if player is None:
        return Response(status_code=204)

    textures = {}
    if player.get("skin") and (SKINS / f"{player['skin']}.png").exists():
        skin = {"url": f"{public_base(request)}/textures/{player['skin']}.png"}
        if player.get("slim"):
            skin["metadata"] = {"model": "slim"}
        textures["SKIN"] = skin

    payload = {
        "timestamp": int(time.time() * 1000),
        "profileId": clean,
        "profileName": player["username"],
        "textures": textures,
    }
    value = base64.b64encode(json.dumps(payload).encode()).decode()
    prop = {"name": "textures", "value": value}
    if not unsigned:
        prop["signature"] = sign(value)
    return {"id": clean, "name": player["username"], "properties": [prop]}


@ygg.post("/api/profiles/minecraft")
async def ygg_lookup(names: list[str]):
    out = []
    for n in names:
        p = PLAYERS.get(n.lower())
        if p:
            out.append({"id": p["uuid"], "name": p["username"]})
    return out


app.include_router(ygg)


# ---------------- API лаунчера ----------------

@app.get("/")
@app.get("/health")
async def health():
    return {"status": "ok", "players": len(PLAYERS), "catalog": len(CATALOG)}


@app.post("/api/upload-skin")
async def upload_skin(
    username: str = Form(...),
    token: str = Form(...),
    slim: bool = Form(False),
    file: UploadFile = File(...),
):
    data = await file.read()
    validate_skin(data)
    player = check_token(username, token)
    player["slim"] = slim
    player["skin"] = store_skin(data)
    _save("players.json", PLAYERS)
    return {"status": "ok", "uuid": player["uuid"], "username": player["username"]}


@app.post("/api/reset-skin")
async def reset_skin(username: str = Form(...), token: str = Form(...)):
    player = check_token(username, token)
    player["skin"] = None
    player["slim"] = False
    _save("players.json", PLAYERS)
    return {"status": "ok"}


@app.get("/textures/{filename}")
async def get_texture(filename: str):
    if not re.fullmatch(r"[0-9a-f]{64}\.png", filename):
        raise HTTPException(404, "not_found")
    f = SKINS / filename
    if not f.exists():
        raise HTTPException(404, "not_found")
    return FileResponse(f, media_type="image/png", headers={"Cache-Control": "public, max-age=31536000, immutable"})


# ---------------- каталог ----------------

async def external_search(query: str, page: int) -> list[dict]:
    """
    Загружает скины через официальный Mojang API. 
    Если поиск пустой — загружает подборку классных игроков для каталога.
    """
    items = []
    q = query.strip()

    # Если поиск пустой, используем дефолтный набор популярных ников для наполнения каталога
    if not q:
        nicks_to_fetch = [
            "Notch", "Dinnerbone", "Jeb_", "Grumm", "Dream", 
            "Technoblade", "MumboJumbo", "Etho", "Stampy", "DanTDM",
            "CaptainSparklez", "Ninja"
        ]
    else:
        # Если пользователь ввел что-то в поиск, ищем конкретный ник
        nicks_to_fetch = [q]

    async with httpx.AsyncClient(timeout=10.0) as client:
        for nick in nicks_to_fetch:
            if not nick or not NICK_RE.fullmatch(nick):
                continue
            try:
                # 1. Получаем UUID по нику через Mojang API
                r = await client.get(f"https://api.mojang.com/users/profiles/minecraft/{nick}")
                if r.status_code != 200:
                    continue
                prof = r.json()
                uuid_str = prof.get("id")
                real_name = prof.get("name", nick)

                # 2. Получаем текстуры скина по UUID
                r_prof = await client.get(f"https://sessionserver.mojang.com/session/minecraft/profile/{uuid_str}")
                if r_prof.status_code != 200:
                    continue
                
                for p in r_prof.json().get("properties", []):
                    if p.get("name") != "textures":
                        continue
                    tex_data = json.loads(base64.b64decode(p.get("value", "")))
                    skin_info = tex_data.get("textures", {}).get("SKIN")
                    if not skin_info:
                        continue
                    
                    texture_url = skin_info.get("url")
                    is_slim = (skin_info.get("metadata") or {}).get("model") == "slim"

                    # Избегаем дубликатов
                    if not any(i["name"].lower() == real_name.lower() for i in items):
                        items.append({
                            "name": real_name,
                            "texture_url": texture_url,
                            "slim": is_slim
                        })
            except Exception:
                continue

    return items


async def add_to_catalog(name: str, data: bytes, slim: bool | None, source: str) -> str:
    img = validate_skin(data)
    skin_id = store_skin(data)
    if skin_id not in CATALOG:
        CATALOG[skin_id] = {
            "id": skin_id,
            "name": name[:48],
            "slim": detect_slim(img) if slim is None else slim,
            "source": source,
            "added": int(time.time()),
        }
        _save("catalog.json", CATALOG)
    return skin_id


async def mojang_lookup(nick: str) -> None:
    """Ищет скин настоящего игрока по нику через официальный API Mojang."""
    async with httpx.AsyncClient(timeout=8) as c:
        r = await c.get(f"https://api.mojang.com/users/profiles/minecraft/{nick}")
        if r.status_code != 200:
            return
        prof = r.json()
        r = await c.get(f"https://sessionserver.mojang.com/session/minecraft/profile/{prof['id']}")
        if r.status_code != 200:
            return
        for p in r.json().get("properties", []):
            if p.get("name") != "textures":
                continue
            tex = json.loads(base64.b64decode(p["value"])).get("textures", {}).get("SKIN")
            if not tex:
                return
            slim = (tex.get("metadata") or {}).get("model") == "slim"
            png = await c.get(tex["url"])
            if png.status_code == 200:
                await add_to_catalog(prof["name"], png.content, slim, "mojang")
            return


@app.get("/api/catalog")
async def catalog(request: Request, q: str = "", page: int = 0, per: int = 24):
    q = q.strip()
    base = public_base(request)

    if page == 0 and q:
        try:
            # 1. Сначала пробуем спарсить сайт-источник по запросу
            external_items = await external_search(q, 0)
            for it in external_items:
                async with httpx.AsyncClient(timeout=10) as c:
                    png = await c.get(it["texture_url"])
                if png.status_code == 200:
                    await add_to_catalog(it["name"], png.content, it.get("slim"), "external")
            
            # 2. Если парсер ничего не нашел И это похоже на ник — только тогда идем в Mojang как запасной вариант
            if not external_items and NICK_RE.fullmatch(q) and not any(c["name"].lower() == q.lower() for c in CATALOG.values()):
                await mojang_lookup(q)
                
        except Exception as e:
            print(f"[Catalog Error]: {e}")

    items = sorted(CATALOG.values(), key=lambda c: c["added"], reverse=True)
    if q:
        items = [c for c in items if q.lower() in c["name"].lower()]

    per = max(1, min(per, 60))
    chunk = items[page * per:(page + 1) * per]
    return {
        "items": [{
            "id": c["id"],
            "name": c["name"],
            "slim": c["slim"],
            "texture": f"{base}/textures/{c['id']}.png",
            "preview": f"{base}/api/preview/{c['id']}.png",
        } for c in chunk],
        "hasMore": (page + 1) * per < len(items),
    }


@app.get("/api/preview/{filename}")
async def preview(filename: str):
    m = re.fullmatch(r"([0-9a-f]{64})\.png", filename)
    if not m:
        raise HTTPException(404, "not_found")
    info = CATALOG.get(m.group(1), {})
    return FileResponse(preview_file(m.group(1), bool(info.get("slim"))), media_type="image/png",
                        headers={"Cache-Control": "public, max-age=86400"})


@app.post("/api/admin/catalog")
async def admin_add(
    name: str = Form(...),
    file: UploadFile = File(...),
    slim: bool | None = Form(None),
    x_admin_key: str = Header(default=""),
):
    if not ADMIN_KEY or not secrets.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(403, "forbidden")
    skin_id = await add_to_catalog(name, await file.read(), slim, "admin")
    return {"status": "ok", "id": skin_id}
