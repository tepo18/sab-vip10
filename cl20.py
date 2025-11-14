#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import json
import base64
import urllib.request
import subprocess
import platform
import threading
import re

# ---------------- مسیر فایل‌ها ----------------
TEXT_NORMAL = "normal20.txt"
TEXT_FINAL = "final20.txt"

LINKS_PATH = [
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/shah.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/shah10.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/shah20.txt",
    "https://raw.githubusercontent.com/parvinxs/Fssociety/main/Fssociety.sub",
    "https://raw.githubusercontent.com/parvinxs/Submahsanetxsparvin/main/Sub.mahsa.xsparvin",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/hy2.html",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hy2",
    "https://raw.githubusercontent.com/tepo80/Trojan/main/hp.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/hy2.txt"
]

MAX_THREADS = 20
MAX_PING_MS = 1200

# ---------------- دریافت خطوط از لینک ----------------
def fetch_lines(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            lines = resp.read().decode(errors="ignore").splitlines()
            return [line.strip() for line in lines if line.strip()]
    except Exception as e:
        print(f"[ERROR] Cannot fetch {url}: {e}")
        return []

# ---------------- حذف خطوط تکراری ----------------
def unique_lines(lines):
    seen = set()
    result = []
    for line in lines:
        if line not in seen:
            result.append(line)
            seen.add(line)
    return result

# ---------------- پینگ ----------------
def ping(host, count=1, timeout=1):
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        cmd = ["ping", param_count, str(count), param_timeout, str(timeout), host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        match = re.search(r'time[=<]\s*(\d+\.?\d*)', output)
        if match:
            return float(match.group(1))
    except:
        pass
    return float('inf')

# ---------------- استخراج هاست و پورت از کانفیگ ----------------
def extract_address(config_line):
    try:
        if config_line.startswith("vmess://"):
            encoded = config_line.split("://", 1)[1].split("#")[0]
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += "=" * (4 - missing_padding)
            data = json.loads(base64.b64decode(encoded).decode('utf-8', errors="ignore"))
            host = data.get("add") or data.get("address")
            port = int(data.get("port", 443))
            return host, port

        elif config_line.startswith("vless://") or config_line.startswith("trojan://"):
            match = re.match(r'^[^:]+://[^@]+@([^:]+):(\d+)', config_line)
            if match:
                return match.group(1), int(match.group(2))

        elif config_line.startswith("hy2://") or config_line.startswith("hysteria2://"):
            match = re.match(r'^[^:]+://([^:]+):(\d+)', config_line)
            if match:
                return match.group(1), int(match.group(2))
    except:
        pass
    return None, None

# ---------------- پردازش پینگ ----------------
def process_ping(configs):
    results = []
    lock = threading.Lock()
    threads = []

    def worker(cfg_line):
        host, port = extract_address(cfg_line)
        if host:
            ping_time = ping(host)
            if ping_time < MAX_PING_MS:
                with lock:
                    results.append((cfg_line, ping_time))

    for line in configs:
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()
        if len(threads) >= MAX_THREADS:
            for th in threads: th.join()
            threads = []

    for t in threads: t.join()
    results.sort(key=lambda x: x[1])
    return [cfg for cfg, _ in results]

# ---------------- ذخیره فایل‌ها ----------------
def save_files(normal_lines, final_lines):
    with open(TEXT_NORMAL, "w", encoding="utf-8") as f:
        f.write("\n".join(normal_lines))
    with open(TEXT_FINAL, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

# ---------------- اجرای اصلی ----------------
def update_all():
    print("[*] Fetching sources...")
    all_lines = []
    for link in LINKS_PATH:
        all_lines.extend(fetch_lines(link))
    print(f"[*] Total lines fetched: {len(all_lines)}")

    all_lines = unique_lines(all_lines)

    print("[*] Stage 1: First ping check (basic filtering)...")
    normal_lines = process_ping(all_lines)
    print(f"[INFO] Saved {len(normal_lines)} configs to {TEXT_NORMAL}")

    print("[*] Stage 2: Detailed ping stability check...")
    final_lines = process_ping(normal_lines)
    print(f"[INFO] Saved {len(final_lines)} configs to {TEXT_FINAL}")

    save_files(normal_lines, final_lines)
    print("[✅] Update complete.")

if __name__ == "__main__":
    print("[*] Starting advanced auto-updater for TXT sources (cl2)...")
    update_all()
