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

# منابع (ساب لینک‌ها)
SUB_SOURCES = [
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
    "https://raw.githubusercontent.com/hamedp-71/Trojan/refs/heads/main/hp.txt",
    "https://zaya.link/Arista_HP_Final",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/hy2.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/trojan.txt"
]

# تنظیمات پین‌گیری
STAGE1_PING_COUNT = 3
STAGE1_TIMEOUT = 5
STAGE1_MAX_MS = 1200

STAGE2_PING_COUNT = 6
STAGE2_TIMEOUT = 10
STAGE2_MAX_MS = 600

MAX_WORKERS = 10


# تابع برای دانلود محتوا از URL
def safe_download(url):
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            return r.text.strip().splitlines()
    except Exception as e:
        print(f"Error downloading {url}: {e}")
    return []


# بررسی Base64 بودن محتوا
def is_base64(s: str) -> bool:
    try:
        if len(s) % 4 == 0 and re.fullmatch(r'[A-Za-z0-9+/=]+', s):
            base64.b64decode(s, validate=True)
            return True
    except Exception:
        return False
    return False


# استخراج host از کانفینگ
def extract_host(config: str):
    m = re.search(r"@([^:/?#\s]+)", config)
    if m:
        return m.group(1)
    m = re.search(r"://([^:/?#\s]+)", config)
    return m.group(1) if m else None


# پین‌گیری برای هر کانفینگ
def ping_host(host: str, ping_count: int, timeout: float):
    """پین‌گیری از هاست و بازگشت مقدار متوسط ms یا None"""
    try:
        output = subprocess.check_output(
            ["ping", "-c", str(ping_count), "-W", str(int(timeout)), host],
            stderr=subprocess.DEVNULL
        ).decode()
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
        return float(match.group(1)) if match else None
    except Exception as e:
        print(f"Ping error for {host}: {e}")
        return None


# تابع برای تست و ذخیره کانفینگ‌های سالم
def test_and_save_sources(SUB_SOURCES):
    valid_configurations = []

    # پردازش هر یک از منابع
    for url in SUB_SOURCES:
        print(f"Processing {url}...")
        config_lines = safe_download(url)

        for line in config_lines:
            if not is_base64(line):  # اگر Base64 نباشد ادامه می‌دهیم
                host = extract_host(line)  # استخراج host از کانفینگ
                if host:
                    ping_result = ping_host(host, STAGE1_PING_COUNT, STAGE1_TIMEOUT)  # پین‌گیری
                    if ping_result is not None and ping_result < STAGE1_MAX_MS:
                        print(f"Ping to {host}: {ping_result} ms")
                        valid_configurations.append(line)
                else:
                    print(f"Invalid config: {line} (host extraction failed)")
            else:
                print(f"Skipping Base64 config: {line}")

    # ذخیره کانفینگ‌های سالم در فایل خروجی اول (ping.txt)
    with open(PING_FILE, "w") as f:
        for config in valid_configurations:
            f.write(config + "\n")

    print(f"Saved {len(valid_configurations)} valid configs to {PING_FILE}")


# فیلتر کردن و ذخیره بهترین کانفینگ‌ها برای مرحله دوم
def filter_best_configs():
    best_configs = []
    with open(PING_FILE, "r") as f:
        lines = f.readlines()

    # پردازش هر خط و پین‌گیری دقیق‌تر
    for line in lines:
        host = extract_host(line.strip())
        if host:
            ping_result = ping_host(host, STAGE2_PING_COUNT, STAGE2_TIMEOUT)  # پین‌گیری مرحله دوم
            if ping_result is not None and ping_result < STAGE2_MAX_MS:
                best_configs.append(line.strip())

    # ذخیره بهترین کانفینگ‌ها در فایل خروجی دوم (best.txt)
    with open(BEST_FILE, "w") as f:
        for config in best_configs:
            f.write(config + "\n")

    print(f"Saved {len(best_configs)} best configs to {BEST_FILE}")


# اجرای کد
if __name__ == "__main__":
    # مرحله اول: پردازش و پین‌گیری از منابع
    test_and_save_sources(SUB_SOURCES)

    # مرحله دوم: فیلتر کردن بهترین کانفینگ‌ها
    filter_best_configs()
