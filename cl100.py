#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from typing import List
import base64
import json

# ---------------- مسیر خروجی ----------------
NORMAL_FILE = "normal100.txt"  # فایل خروجی نهایی
FINAL_FILE = "final100.txt"    # فایل خروجی فینال

# ---------------- منابع ساب لینک ----------------
LINKS_PATH = [
    "https://billowing-king-badd.shah98-tepo98.workers.dev/sub?token=ad2787e72ea01b52a90cc686afe1896f",
    "https://almasi.ahsan-tepo1383online.workers.dev/sub/sub",
    "https://xnzvhfevu8ms.shah98-tepo98.workers.dev/feed/ZEUS-77IELBGK",
    "https://small-pond-676-e-d-g-e.batool-sogeli.workers.dev/sub?token=54e533fc74493379c95453c419066252",
    "https://wlzmgdefumms.ahsan-tepo1390.workers.dev/feed/jjjjjjjjjjjjj",
    "https://avopt-efoxs7qnam.pages.dev/Gp5phgTfSXuWNe/sub/raw?app=xray#%F0%9F%92%A6%20BPB%20Raw",
    "https://n-h-a-n-98.ahsan-tepo1383online.workers.dev/sync?sub=d5d4cc2f47b3c71bf88e5a2b9cc9de4b&flag=raw",
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://frosty-robin-2c97.tepo3360.workers.dev/sub?token=69c2fbc1aeb0204a096e60dc14f09370",
    "https://xnzvhfevu8ms.shah98-tepo98.workers.dev/feed/ZEUS-77IELBGK"
    
    # لینک‌های دیگر...
]

MAX_THREADS = 10
PING_TIMEOUT = 2.0  # تایم اوت پینگ
PING_MAX_MS = 1200  # بالاتر از این مقدار تایم اوت محسوب می‌شود

FILE_HEADER_TEXT = "//profile-title: base64:2YfZhduM2LTZhyDZgdi52KfZhCDwn5iO8J+YjvCfmI4gaGFtZWRwNzE="

# ===================== توابع =====================

def fetch_link(url: str) -> List[str]:
    """دریافت داده‌ها از لینک و نادیده گرفتن لینک‌های با مشکلات فرمت"""
    try:
        r = requests.get(url, timeout=15)
        
        if r.status_code == 200:
            content = r.text.strip()

            # بررسی اگر محتوای لینک JSON باشد
            try:
                json_data = json.loads(content)
                return [l.strip() for l in json_data if l.strip()]
            except json.JSONDecodeError:
                # اگر نتوانستیم به JSON تبدیل کنیم، بررسی کنیم که Base64 است یا نه
                try:
                    base64.b64decode(content)
                    return []  # لینک Base64 را رد می‌کنیم
                except:
                    return [content]  # در صورتی که لینک مشکل نداشت
        else:
            print(f"[⚠️] Failed to fetch {url}: Status Code {r.status_code}")
            return []
    except Exception as e:
        print(f"[⚠️] Cannot fetch {url}: {e}")
        return []

def is_valid_config(line: str) -> bool:
    """بررسی معتبر بودن تنظیمات"""
    line = line.strip()
    if not line or len(line) < 5:
        return False
    lower = line.lower()
    if "pin=0" in lower or "pin=red" in lower or "pin=قرمز" in lower:
        return False
    return True

def parse_config_line(line: str):
    """تجزیه خط تنظیمات پروکسی"""
    try:
        line = urllib.parse.unquote(line.strip())
        for p in ["vmess", "vless", "trojan", "hy2", "hysteria2", "ss", "socks", "wireguard"]:
            if line.startswith(p + "://"):
                return line
    except:
        pass
    return None

def tcp_test(host: str, port: int, timeout=3) -> bool:
    """آزمون پینگ برای پروکسی"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def process_configs(lines: List[str], precise_test=False) -> List[str]:
    """پردازش تنظیمات پروکسی"""
    valid_configs = []
    lock = threading.Lock()

    def worker(line):
        cfg = parse_config_line(line)
        passed = False

        if cfg:
            try:
                import re
                m = re.search(r"@([^:]+):(\d+)", cfg)
                host, port = (m.group(1), int(m.group(2))) if m else ("", 443)

                if precise_test and host:
                    passed = tcp_test(host, port)
                else:
                    passed = True
            except:
                passed = False

        if passed and is_valid_config(line):
            with lock:
                valid_configs.append(line)

    threads = []
    for line in lines:
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # حذف تکراری
    final_list = list(dict.fromkeys(valid_configs))
    return final_list

def save_outputs(lines: List[str]):
    """ذخیره خروجی‌ها به فایل‌ها"""
    try:
        with open(NORMAL_FILE, "w", encoding="utf-8") as f:
            f.write("")
        with open(FINAL_FILE, "w", encoding="utf-8") as f:
            f.write("")

        # مرحله نرمال
        normal_lines = lines
        with open(NORMAL_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join([FILE_HEADER_TEXT] + normal_lines))
        print(f"[ℹ️] Stage 1: {len(normal_lines)} configs saved to {NORMAL_FILE}")

        # مرحله فینال با تست دقیق
        final_lines = process_configs(normal_lines, precise_test=True)
        with open(FINAL_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(final_lines))
        print(f"[ℹ️] Stage 2: {len(final_lines)} configs saved to {FINAL_FILE}")

        print(f"[✅] Update complete. Total sources: {len(lines)}")
        print(f"  -> Normal configs: {len(normal_lines)}")
        print(f"  -> Final configs: {len(final_lines)}")

    except Exception as e:
        print(f"[❌] Error saving files: {e}")

def update_subs():
    """بروزرسانی و دریافت تنظیمات از منابع"""
    all_lines = []

    for url in LINKS_PATH:
        fetched = fetch_link(url)
        if not fetched:
            print(f"[⚠️] Cannot fetch or empty source: {url}")
        else:
            all_lines.extend(fetched)

    print(f"[*] Total lines fetched from sources: {len(all_lines)}")
    all_lines = process_configs(all_lines)
    save_outputs(all_lines)

# ===================== اجرای دستی =====================
if __name__ == "__main__":
    print("[*] Starting manual subscription update...")
    update_subs()
    print("[*] Done. Run this script manually whenever needed.")
