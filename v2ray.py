import requests
import base64
import json
import os

# لیست منابع سورس ساب لینک‌ها
LINK_PATH = [
    "https://raw.githubusercontent.com/tepo18/tepo90/main/final2.txt",
    "https://raw.githubusercontent.com/tepo80/sab-vip90/main/almasi.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/tepo80/tepo80/refs/heads/main/shah.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/hamedp-71/v2go_NEW/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/tepo98/kv98/main/final.txt",
    "https://raw.githubusercontent.com/some-user/other-repo/main/file1.txt",  # این‌ها مثال هستند
    "https://raw.githubusercontent.com/some-user/other-repo/main/file2.txt"
]

# توابع برای پردازش لینک‌ها و تبدیل به Base64
def b64e(s: str) -> str:
    """تبدیل رشته به Base64"""
    return base64.b64encode(s.encode()).decode()

def fix_vmess(link):
    """تبدیل لینک vmess به Base64"""
    try:
        raw = link.replace("vmess://", "")
        j = json.loads(base64.b64decode(raw + "===").decode())
        clean = json.dumps(j, separators=(",", ":"))
        return "vmess://" + b64e(clean)
    except Exception as e:
        return None

def fix_ss(link):
    """تبدیل لینک ss به Base64"""
    try:
        raw = link.replace("ss://", "").split("#")[0]
        base64.b64decode(raw + "===")
        return "ss://" + raw
    except Exception as e:
        try:
            return "ss://" + b64e(raw)
        except Exception as e:
            return None

def normalize(line):
    """تبدیل خطوط پروتکل‌ها به Base64"""
    line = line.strip()
    if not line:
        return None

    if line.startswith("vmess://"):
        return fix_vmess(line)
    if line.startswith("ss://"):
        return fix_ss(line)
    if line.startswith((
        "vless://", "trojan://", "hysteria://", "hysteria2://",
        "tuic://", "socks://", "http://", "https://"
    )):
        return line
    return None

# ================== پردازش فایل‌ها ==================
def process_subs():
    all_configs = []

    # ایجاد پوشه برای ذخیره خروجی‌ها اگر وجود نداشت
    if not os.path.exists("output"):
        os.makedirs("output")

    # دریافت لینک‌ها از منابع
    for idx, url in enumerate(LINK_PATH[:10]):  # حداکثر 10 لینک
        print(f"Processing source {idx + 1}: {url}")
        
        try:
            response = requests.get(url)
            response.raise_for_status()  # بررسی وضعیت پاسخ
            lines = response.text.splitlines()
            
            # پردازش هر خط از محتوا
            for line in lines:
                processed_line = normalize(line)
                if processed_line:
                    all_configs.append(processed_line)

            # ذخیره‌سازی در فایل خروجی برای هر ساب لینک
            output_filename = f"output/v2ray{idx + 1}.txt"  # خروجی از v2ray.txt تا v2ray10.txt
            with open(output_filename, "w", encoding="utf-8") as output_file:
                output_file.write("\n".join(all_configs))

            # Reset the list for the next source
            all_configs = []

        except requests.exceptions.RequestException as e:
            print(f"Error processing {url}: {e}")
            continue  # اگر خطایی در پردازش بود، ادامه بدهید به لینک بعدی

    print("[✓] Processing completed!")

# اجرای کد
if __name__ == "__main__":
    process_subs()
