#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
import requests
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ---------------- مسیر خروجی ----------------
NORMAL_YAML = "normal.yaml"
FINAL_YAML = "final.yaml"

# ---------------- منابع ساب لینک ----------------
LINKS_PATH = [
    "https://raw.githubusercontent.com/tepo80/tepo80/refs/heads/main/shah.yaml"
    # می‌توانید لینک‌های بیشتری اضافه کنید
]

MAX_THREADS = 10
PING_TIMEOUT = 2.0  # ثانیه
PING_MAX_MS = 1200  # بالاتر از این تایم اوت است

# ---------------- توابع کمکی ----------------
def tcp_ping_ms(host, port, timeout=2.0):
    try:
        start = time.monotonic()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return int((time.monotonic() - start) * 1000)
    except:
        return None

def fetch_yaml(url):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return yaml.safe_load(r.text)
    except:
        pass
    return {}

def extract_proxies(yaml_data):
    return yaml_data.get("proxies", [])

def check_proxy(proxy):
    host = proxy.get("server")
    port = proxy.get("port")
    if host and port:
        latency = tcp_ping_ms(host, port, timeout=PING_TIMEOUT)
        if latency is not None and latency <= PING_MAX_MS:
            return proxy
    return None

def process_proxies(proxies):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = {ex.submit(check_proxy, p): p for p in proxies}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    results.append(res)
            except:
                continue
    return results

def merge_yaml_blocks(yaml_blocks):
    merged = {"proxies": [], "proxy-groups": [], "rules": []}
    for y in yaml_blocks:
        if not y: 
            continue
        if "proxies" in y:
            merged["proxies"].extend(y["proxies"])
        if "proxy-groups" in y:
            merged["proxy-groups"].extend(y["proxy-groups"])
        if "rules" in y:
            merged["rules"].extend(y["rules"])
    return merged

# ---------------- ذخیره فایل YAML ----------------
def save_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

# ---------------- اجرای اصلی ----------------
def update_all():
    # ابتدا خالی کردن خروجی‌ها
    save_yaml(NORMAL_YAML, {"proxies": [], "proxy-groups": [], "rules": []})
    save_yaml(FINAL_YAML, {"proxies": [], "proxy-groups": [], "rules": []})

    print("[*] Fetching sources...")
    yaml_blocks = []
    for link in LINKS_PATH:
        y = fetch_yaml(link)
        if y:
            yaml_blocks.append(y)

    merged = merge_yaml_blocks(yaml_blocks)
    proxies = extract_proxies(merged)
    print(f"[*] Total proxies fetched: {len(proxies)}")

    print("[*] Stage 1: Normal ping check...")
    normal_proxies = process_proxies(proxies)
    merged["proxies"] = normal_proxies
    save_yaml(NORMAL_YAML, merged)
    print(f"[INFO] Saved {len(normal_proxies)} proxies to {NORMAL_YAML}")

    print("[*] Stage 2: Detailed ping check for final output...")
    final_proxies = process_proxies(normal_proxies)
    merged["proxies"] = final_proxies
    save_yaml(FINAL_YAML, merged)
    print(f"[✅] Saved {len(final_proxies)} proxies to {FINAL_YAML}")

if __name__ == "__main__":
    print("[*] Starting YAML Proxy Health Checker (cl10.py)...")
    update_all()
