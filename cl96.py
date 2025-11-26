#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import base64
import requests
import subprocess
import concurrent.futures

# فایل‌های خروجی
PING_FILE = "ping.txt"
BEST_FILE = "best.txt"

# منابع سورس
SUB_SOURCES = [
    # اینجا خالی گذاشته شده – خودت اضافه می‌کنی
    # "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/.../final.txt",
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/hamedp-71/Trojan/refs/heads/main/hp.txt",
    "https://zaya.link/Arista_HP_Final",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/hy2.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/trojan.txt",
]

# تنظیمات پین‌گیری
STAGE1_PING_COUNT = 3
STAGE1_TIMEOUT = 5
STAGE1_MAX_MS = 1200

STAGE2_PING_COUNT = 6
STAGE2_TIMEOUT = 10
STAGE2_MAX_MS = 600

MAX_WORKERS = 10


def safe_download(url):
    """برای دانلود محتویات URL با امنیت"""
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            return r.text.strip().splitlines()
    except:
        return None
    return None


def maybe_base64_decode(text):
    """بررسی و دیکود کردن BASE64"""
    try:
        if len(text) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", text):
            return base64.b64decode(text).decode(errors="ignore")
    except:
        return text
    return text


def ping_host(host, ping_count, timeout):
    """پین‌گیری از آدرس"""
    try:
        output = subprocess.check_output(
            ["ping", "-c", str(ping_count), "-W", str(int(timeout)), host],
            stderr=subprocess.DEVNULL
        ).decode()
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
        return float(match.group(1)) if match else None
    except Exception:
        return None


def classify_ping(avg_ms, good_thr, warn_thr):
    """کلاس‌بندی وضعیت پین"""
    if avg_ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    if avg_ms < good_thr:
        return "good", "[bold green][GOOD][/bold green]"
    if avg_ms < warn_thr:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"


def process_configs(configs):
    """پین‌گیری و پردازش کانفینگ‌ها"""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_cfg = {executor.submit(ping_host, cfg, STAGE1_PING_COUNT, STAGE1_TIMEOUT): cfg for cfg in configs}
        for future in concurrent.futures.as_completed(future_to_cfg):
            cfg = future_to_cfg[future]
            ping = future.result()
            status, label = classify_ping(ping, STAGE1_MAX_MS, STAGE2_MAX_MS)
            results.append((cfg, status, ping))
    return results


def filter_and_save(results, stage, filename):
    """فیلتر کردن و ذخیره نتایج در فایل"""
    valid_configs = [cfg for cfg, status, ping in results if ping is not None and status == "good" and ping < stage]
    with open(filename, "w", encoding="utf-8") as f:
        for item in valid_configs:
            f.write(item + "\n")


def main():
    """تابع اصلی"""
    all_configs = []
    
    # دانلود منابع
    for url in SUB_SOURCES:
        print(f"دانلود {url}")
        configs = safe_download(url)
        if configs:
            all_configs.extend(configs)

    if not all_configs:
        print("هیچ کانفیگی یافت نشد.")
        return

    # مرحله اول پین‌گیری
    print("مرحله اول پین‌گیری در حال انجام است...")
    stage1_results = process_configs(all_configs)

    # ذخیره نتایج مرحله اول در فایل ping.txt
    print(f"ذخیره نتایج مرحله اول در فایل {PING_FILE}...")
    filter_and_save(stage1_results, STAGE1_MAX_MS, PING_FILE)

    # مرحله دوم پین‌گیری دقیق‌تر
    print("مرحله دوم پین‌گیری دقیق‌تر در حال انجام است...")
    with open(PING_FILE, "r", encoding="utf-8") as f:
        stage2_configs = f.read().splitlines()

    stage2_results = process_configs(stage2_configs)

    # ذخیره نتایج مرحله دوم در فایل best.txt
    print(f"ذخیره نتایج مرحله دوم در فایل {BEST_FILE}...")
    filter_and_save(stage2_results, STAGE2_MAX_MS, BEST_FILE)

    print("پایان کار.")


if __name__ == "__main__":
    main()
