#!/data/data/com.termux/files/usr/bin/python3
import os, re, json, yaml, subprocess, base64, socket, time, requests
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------
# 1)  ساب‌لینک‌ها (هرچقدر خواستی اضافه کن)
# ---------------------------------------------------
LINKS_PATH = [
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/refs/heads/main/All_Configs_Sub.txt"
]

# ---------------------------------------------------
# 2)  مکان ثابت ذخیره خروجی
# ---------------------------------------------------

OUT_PATH = os.path.join(os.path.dirname(__file__), "shah.yaml")
# ---------------------------------------------------
# 3)  دانلود اتومات محتوا از تمام ساب‌لینک‌ها
# ---------------------------------------------------
def download_all_sources():
    all_text = ""
    for url in LINKS_PATH:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                all_text += "\n" + r.text
        except:
            pass
    return all_text

content = download_all_sources()

# ---------------------------------------------------
# 4)  توابع کمکی – حفظ‌شده از نسخه اصلی
# ---------------------------------------------------
def b64fix(s: str) -> str:
    s = s.strip().replace("\n", "").replace(" ", "")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return s

def safe_int(x, default=0):
    try:
        return int(x)
    except:
        return default

def sanitize(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"[^A-Za-z0-9_\- .]", "", str(s)).strip()

_used_names = set()
def uniq_name(base: str) -> str:
    base = sanitize(base) or "Proxy"
    name = base
    i = 2
    while name in _used_names:
        name = f"{base} {i}"
        i += 1
    _used_names.add(name)
    return name

def tail(s: str, n=6):
    if not s:
        return ""
    s2 = re.sub(r"[-]", "", s)
    return s2[-n:] if len(s2) >= n else s2

def tcp_ping_ms(host, port, timeout=2.0):
    try:
        start = time.monotonic()
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.close()
        return int((time.monotonic() - start) * 1000)
    except:
        return None

def extract_json_objects(text):
    objs, stack, start = [], [], None
    for i, c in enumerate(text):
        if c == '{':
            if not stack:
                start = i
            stack.append(c)
        elif c == '}':
            if stack:
                stack.pop()
                if not stack and start is not None:
                    objs.append(text[start:i+1])
                    start = None
    return objs

# ---------------------------------------------------
# 5) شروع پردازش
# ---------------------------------------------------
proxies = []

# ---------------------------------------------------
# JSON fragment parsing
# ---------------------------------------------------
for frag in extract_json_objects(content):
    try:
        obj = json.loads(frag)
    except:
        continue
    outbounds = obj.get("outbounds", []) or []
    for ob in outbounds:
        proto = (ob.get("protocol") or "").lower()
        if proto not in ("vless", "vmess", "trojan", "shadowsocks"):
            continue
        stream = ob.get("streamSettings") or {}
        net = (stream.get("network") or "tcp").lower()
        security = (stream.get("security") or "").lower()
        tls_flag = security in ("tls", "reality")

        # VLESS & VMESS
        if proto in ("vless", "vmess"):
            try:
                vnext = (ob.get("settings") or {}).get("vnext", [])[0]
                user = (vnext.get("users") or [])[0]
            except:
                continue
            server = vnext.get("address") or ""
            port = safe_int(vnext.get("port"), 0)
            uid = user.get("id") or ""
            if not (server and port and uid):
                continue
            base = f"{proto}-{server}-{tail(uid)}"
            name = uniq_name(base)
            p = {
                "name": name,
                "type": proto,
                "server": server,
                "port": port,
                "udp": True,
                "network": net
            }
            if proto == "vless":
                p["uuid"] = uid
                p["encryption"] = "none"
            else:
                p["uuid"] = uid
                p["alterId"] = safe_int(user.get("alterId", user.get("aid", 0)))
                p["cipher"] = user.get("cipher", "auto")
            if tls_flag:
                sni = (stream.get("tlsSettings") or {}).get("serverName") or server
                p["tls"] = True
                p["servername"] = sni
            if net == "ws":
                ws = stream.get("wsSettings") or {}
                path = ws.get("path") or "/"
                headers = ws.get("headers") or {}
                p["ws-opts"] = {"path": path}
                if headers:
                    p["ws-opts"]["headers"] = headers
            proxies.append(p)

        # Trojan
        elif proto == "trojan":
            try:
                s = (ob.get("settings") or {}).get("servers", [])[0]
            except:
                continue
            server = s.get("address") or ""
            port = safe_int(s.get("port"), 0)
            pwd = s.get("password") or ""
            if not (server and port and pwd):
                continue
            name = uniq_name(f"trojan-{server}-{tail(pwd)}")
            p = {
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": pwd,
                "udp": True,
                "network": "tcp"
            }
            proxies.append(p)

        # Shadowsocks
        elif proto == "shadowsocks":
            try:
                s = (ob.get("settings") or {}).get("servers", [])[0]
            except:
                continue
            server = s.get("address") or ""
            port = safe_int(s.get("port"), 0)
            cipher = s.get("method") or s.get("cipher") or ""
            password = s.get("password") or ""
            if not (server and port and cipher and password):
                continue
            name = uniq_name(f"ss-{server}-{port}")
            p = {
                "name": name,
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": cipher,
                "password": password,
                "udp": True
            }
            proxies.append(p)

# ---------------------------------------------------
# لینک‌های خطی (vless:// vmess:// ...)
# ---------------------------------------------------
for line in [ln.strip() for ln in content.splitlines() if ln.strip()]:
    try:
        # vless
        if line.startswith("vless://"):
            parsed = urlparse(line)
            uid = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port or 443
            q = parse_qs(parsed.query)
            net = (q.get("type", ["tcp"])[0]).lower()
            tls_flag = (q.get("security", [""])[0]).lower() in ("tls", "reality")
            if not (uid and host):
                continue
            name = uniq_name(f"vless-{host}-{tail(uid)}")
            p = {
                "name": name, "type": "vless",
                "server": host, "port": port,
                "uuid": uid, "udp": True, "encryption": "none",
                "network": net
            }
            proxies.append(p)

        # vmess
        elif line.startswith("vmess://"):
            payload = line[8:]
            try:
                decoded = base64.b64decode(b64fix(payload)).decode(errors="ignore")
                info = json.loads(decoded)
            except:
                continue
            host = info.get("add") or ""
            port = safe_int(info.get("port"), 0)
            uid = info.get("id") or ""
            if not (host and port and uid):
                continue
            name = uniq_name(f"vmess-{host}-{tail(uid)}")
            p = {
                "name": name, "type": "vmess",
                "server": host, "port": port,
                "uuid": uid,
                "alterId": safe_int(info.get("aid", 0)),
                "cipher": info.get("scy", "auto"),
                "udp": True
            }
            proxies.append(p)

        # trojan://
        elif line.startswith("trojan://"):
            parsed = urlparse(line)
            pwd = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port or 443
            if not (pwd and host):
                continue
            name = uniq_name(f"trojan-{host}-{tail(pwd)}")
            p = {
                "name": name, "type": "trojan",
                "server": host, "port": port,
                "password": pwd, "udp": True
            }
            proxies.append(p)

        # ss://
        elif line.startswith("ss://"):
            try:
                after = line[5:]
                if "@" in after and ":" in after.split("@", 1)[0]:
                    cred, rest = after.split("@", 1)
                    if ":" in cred:
                        method, password = cred.split(":", 1)
                    else:
                        continue
                    host_port = rest.split("#", 1)[0]
                    host, port = host_port.rsplit(":", 1)
                else:
                    b64cred, rest = after.split("@", 1)
                    method_password = base64.urlsafe_b64decode(b64fix(b64cred)).decode()
                    method, password = method_password.split(":", 1)
                    host_port = rest.split("#", 1)[0]
                    host, port = host_port.rsplit(":", 1)
                port = safe_int(port, 0)
                if not (method and password and host and port):
                    continue
                name = uniq_name(f"ss-{host}-{port}")
                p = {
                    "name": name, "type": "ss",
                    "server": host, "port": port,
                    "cipher": method, "password": password, "udp": True
                }
                proxies.append(p)
            except:
                continue

    except:
        continue

# ---------------------------------------------------
# 6) تست پینگ
# ---------------------------------------------------
def check_and_attach_ping(proxy):
    host = proxy.get("server")
    port = proxy.get("port")
    if not host or not port:
        proxy["ping"] = None
        proxy["status"] = "dead"
        return proxy
    lat = tcp_ping_ms(host, port, timeout=2.0)
    proxy["ping"] = lat
    proxy["status"] = "ok" if lat is not None else "dead"
    return proxy

results = []
if proxies:
    max_workers = min(40, len(proxies))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(check_and_attach_ping, p): p for p in proxies}
        for fut in as_completed(futs):
            try:
                res = fut.result()
                results.append(res)
            except:
                pass

name_map = {p["name"]: p for p in results}
final_proxies = [name_map.get(p["name"], p) for p in proxies]

good = [p for p in final_proxies if p.get("status") == "ok"]
good_sorted = sorted(good, key=lambda x: x.get("ping", 99999))

proxy_names = [p["name"] for p in final_proxies]

# ---------------------------------------------------
# 7) نام گروه‌ها
# ---------------------------------------------------
Select = "🎯🚀 انتخاب دستی🚀🎯"
Auto = "📌🌐 بهترین پینگ🌐📌"
Stable = "🔗🏆پایدار🏆🔗"
Fallback = "💢⚡فالبک⚡💢"
DIRECT = "🌟♂️ دایرکت♂️🌟"
Block = "♨️🎖بلوسک🎖♨️"

# ---------------------------------------------------
# 8) ساخت نهایی YAML
# ---------------------------------------------------
config = {
    "proxies": final_proxies,
    "proxy-groups": [
        {"name": Select, "type": "select", "proxies": [Auto, Stable, Fallback, "DIRECT"] + proxy_names},
        {"name": Auto, "type": "url-test", "url": "https://www.gstatic.com/generate_204",
         "interval": 25, "tolerance": 50, "proxies": proxy_names},
        {"name": Stable, "type": "fallback", "url": "https://www.gstatic.com/generate_204",
         "interval": 30, "proxies": proxy_names},
        {"name": Fallback, "type": "fallback", "url": "https://www.gstatic.com/generate_204",
         "interval": 20, "timeout": 3, "tolerance": 50, "proxies": proxy_names}
    ],
    "rules": [f"MATCH,{Select}"]
}

with open(OUT_PATH, "w", encoding="utf-8") as f:
    yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

print(f"[✅] Saved {len(final_proxies)} proxies to {OUT_PATH}")

# ---------------------------------------------------
# 9) Auto-Switch
# ---------------------------------------------------
if len(good_sorted) >= 2:
    proxy1, proxy2 = good_sorted[0], good_sorted[1]
    print(f"[⚡] Auto-switch between: {proxy1['name']} & {proxy2['name']}")

    import threading

    def auto_switch_loop():
        while True:
            ping1 = tcp_ping_ms(proxy1["server"], proxy1["port"], timeout=1)
            ping2 = tcp_ping_ms(proxy2["server"], proxy2["port"], timeout=1)

            if ping1 is None:
                active, other = proxy2, proxy1
            elif ping2 is None:
                active, other = proxy1, proxy2
            else:
                active, other = (proxy1, proxy2) if ping1 <= ping2 else (proxy2, proxy1)

            for group in config["proxy-groups"]:
                if group["name"] == Fallback:
                    group["proxies"] = [active["name"], other["name"]]
                    break

            with open(OUT_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

            time.sleep(3)

    threading.Thread(target=auto_switch_loop, daemon=True).start()
