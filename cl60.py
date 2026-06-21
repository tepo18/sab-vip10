تتعب #!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import threading
import time
import requests
import base64
import urllib.parse
import socket
from typing import List

# ===================== تنظیمات =====================
TEXT_PATH = "normal60.txt"
FIN_PATH = "final60.txt"

LINK_PATH = [
    "1) https://trojan1.ahsan-tepo1383online.workers.dev/sub/172.67.172.49",
    "2) https://almasi.ahsan-tepo1383online.workers.dev/sub/sub",
    "3) https://luffy-panel2.onrender.com/sub/Default",
    "4) https://parsa-panel-ke449.ahsan-tepo1383online.workers.dev/sub?id=e1721c91-d9b0-452e-b7da-739b27f8e2bf",
    "5) https://onkt1jnzjbwpxduq337o6t15ojy8kuxv.ahsan-tepo1383online.workers.dev/sub/normal/VqN7DVtTop%40lV0_l?app=xray#💦 BPB Normal",
    "6) https://onkt1jnzjbwpxduq337o6t15ojy8kuxv.ahsan-tepo1383online.workers.dev/sub/raw/VqN7DVtTop%40lV0_l?app=xray#💦 BPB Raw",
    "7) https://broad-hall-0e18.ahsan-tepo1383online.workers.dev/sync?sub=nahan",
    "8) https://nahan206-sunset-ccff.ahsan-tepo1383online.workers.dev/sub?token=b2be217d6e2759813c2b2af7b02ab0f9"
]


FILE_HEADER_TEXT = "//profile-title: base64:2YfZhduM2LTZhyDZgdi52KfZhCDwn5iO8J+YjvCfmI4gaGFtZWRwNzE="

# ===================== توابع =====================

def fetch_link(url: str) -> List[str]:
    """دریافت خطوط از یک لینک"""
    try:
        time.sleep(0.5)  # جلوگیری از اسپم درخواست‌ها
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            lines = r.text.splitlines()
            return [l.strip() for l in lines if l.strip()]
        else:
            print(f"[⚠️] {url} returned status {r.status_code}")
    except Exception as e:
        print(f"[⚠️] Cannot fetch {url}: {e}")
    return []


def is_valid_config(line: str) -> bool:
    """بررسی اولیه اعتبار کانفیگ"""
    line = line.strip()
    if not line or len(line) < 5:
        return False
    lower = line.lower()
    if "pin=0" in lower or "pin=red" in lower or "pin=قرمز" in lower:
        return False
    return True


def parse_config_line(line: str):
    """تجزیه خط برای شناسایی نوع پروتکل"""
    try:
        line = urllib.parse.unquote(line.strip())
        for p in ["vmess", "vless", "trojan", "hy2", "hysteria2", "ss", "socks", "wireguard"]:
            if line.startswith(p + "://"):
                return line
    except:
        pass
    return None


def tcp_test(host: str, port: int, timeout=3) -> bool:
    """تست TCP برای بررسی پورت و اتصال"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False


def process_configs(lines: List[str], precise_test=False) -> List[str]:
    """پردازش کانفیگ‌ها با فیلتر و تست شبکه"""
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

    # جلوگیری از گیرکردن threadها
    for t in threads:
        t.join(timeout=10)

    # حذف تکراری‌ها
    final_list = list(dict.fromkeys(valid_configs))
    return final_list


def save_outputs(lines: List[str]):
    """ذخیره نهایی فایل‌ها"""
    try:
        if not lines:
            print("[❌] No valid lines to save.")
            return

        # مرحله ۱: نرمال
        normal_lines = lines
        with open(TEXT_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join([FILE_HEADER_TEXT] + normal_lines))
        print(f"[ℹ️] Stage 1: {len(normal_lines)} configs saved to {TEXT_PATH}")

        # مرحله ۲: فینال با تست دقیق
        final_lines = process_configs(normal_lines, precise_test=True)
        with open(FIN_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(final_lines))
        print(f"[ℹ️] Stage 2: {len(final_lines)} configs saved to {FIN_PATH}")

        print(f"[✅] Update complete. Total sources: {len(lines)}")
        print(f"  -> Normal60 configs: {len(normal_lines)}")
        print(f"  -> Final60 configs: {len(final_lines)}")

    except Exception as e:
        print(f"[❌] Error saving files: {e}")


def update_subs():
    """دریافت و پردازش منابع"""
    all_lines = []

    for url in LINK_PATH:
        fetched = fetch_link(url)
        if not fetched:
            print(f"[⚠️] Cannot fetch or empty source: {url}")
        else:
            all_lines.extend(fetched)

    print(f"[*] Total lines fetched from sources: {len(all_lines)}")
    all_lines = process_configs(all_lines)

    if not all_lines:
        print("[❌] No valid configs fetched.")
        return

    save_outputs(all_lines)


# ===================== اجرای دستی =====================
if __name__ == "__main__":
    print("[*] Starting manual subscription update...")
    update_subs()
    print("[*] Done. Run this script manually whenever needed.")
