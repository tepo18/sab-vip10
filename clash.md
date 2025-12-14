 خودتان کنید.

فایل پیکربندی
فایل پیکربندی اصلی config.yaml`.` نام دارد. به طور پیش‌فرض، Clash $HOME/.config/clashفایل پیکربندی را از دایرکتوری `.config.js` می‌خواند. اگر این دایرکتوری وجود نداشته باشد، Clash یک فایل پیکربندی مینیمال در آن مکان ایجاد می‌کند.

اگر می‌خواهید فایل پیکربندی را در جای دیگری قرار دهید (برای مثال /etc/clash)، می‌توانید از گزینه‌های خط فرمان -dبرای مشخص کردن دایرکتوری پیکربندی استفاده کنید:

پوسته
clash -d . # current directory
clash -d /etc/clash
به عنوان یک روش جایگزین، می‌توانید از این گزینه -fبرای مشخص کردن یک فایل پیکربندی استفاده کنید:

پوسته
clash -f ./config.yaml
clash -f /etc/clash/config.yaml
نحو ویژه
فایل‌های پیکربندی Clash دارای سینتکس خاصی هستند که ممکن است لازم باشد با آنها آشنا باشید:

آدرس IPv6
شما باید از براکت ( []) برای قرار دادن آدرس IPv6 استفاده کنید، برای مثال:

متن
[aaaa::a8aa:ff:fe09:57d8]
تطبیق نام دامنه wildcard در DNS
در برخی موارد، شما نیاز دارید که نام‌های دامنه wildcard را مطابقت دهید. برای مثال، هنگام تنظیم Clash DNS ، ممکن است بخواهید localdomainتمام زیر دامنه‌های یک دامنه مشخص را مطابقت دهید.

کلش (Clash) از تطبیق نام‌های دامنه‌ی wildcard در سطوح مختلف پیکربندی DNS، با سینتکس زیر پشتیبانی می‌کند:

نکته

هر نام دامنه‌ای که حاوی این کاراکترها باشد باید 'داخل علامت نقل قول () قرار گیرد. برای مثال، '*.google.com'. نام‌های دامنه استاتیک اولویت بالاتری نسبت به نام‌های دامنه wildcard دارند (foo.example.com > *.example.com > .example.com).

*برای تطبیق زیر دامنه‌های wildcard تک سطحی از علامت ستاره ( ) استفاده کنید .

بیان	مطابقت	عدم تطابق
*.google.com	www.google.com	google.com
*.bar.google.com	foo.bar.google.com	bar.google.com
*.*.google.com	thoughtful.sandbox.google.com	one.two.three.google.com
.برای تطبیق زیر دامنه‌های wildcard چند سطحی از نقطه () استفاده کنید .

بیان	مطابقت	عدم تطابق
.google.com	www.google.com	google.com
.google.com	thoughtful.sandbox.google.com	google.com
.google.com	one.two.three.google.com	google.com
+برای تطبیق زیر دامنه‌های wildcard چند سطحی از علامت بعلاوه ( ) استفاده کنید .

+وایلدکاردها مشابه سایر روش‌ها عمل می‌کنند DOMAIN-SUFFIXو به شما امکان می‌دهند تطبیق سریع را در چندین سطح به طور همزمان انجام دهید.

بیان	مطابقت
+.google.com	google.com
+.google.com	www.google.com
+.google.com	thoughtful.sandbox.google.com
+.google.com	one.two.three.google.com
صفحه قبلی
معرفی کردن
، از جمله:

جوراب5
HTTP(S)
تغییر مسیر TCP
تی‌پی‌پروکسی تی‌پی‌سی
تی‌پروکسی یو‌دی‌پی
دستگاه‌های TUN لینوکس (فقط نسخه پریمیوم)
تمام اتصالات ورودی توسط یک موتور تطبیق قوانین داخلی یکسان مدیریت می‌شوند. به عبارت دیگر، Clash در حال حاضر از تنظیم مجموعه قوانین مختلف برای پروتکل‌های ورودی مختلف پشتیبانی نمی‌کند.

پیکربندی
یامل
# HTTP(S) 代理服务端口
# port: 7890

# SOCKS5 代理服务端口
socks-port: 7891

# HTTP(S) 和 SOCKS4(A)/SOCKS5 代理服务共用一个端口
mixed-port: 7890

# Linux 和 macOS 的透明代理服务端口 (TCP 和 TProxy UDP 重定向)
# redir-port: 7892

# Linux 的透明代理服务端口 (TProxy TCP 和 TProxy UDP)
# tproxy-port: 7893

# 设置为 true 以允许来自其他 LAN IP 地址的连接
# allow-lan: false
پورت مختلط
پورت ترکیبی، پورت خاصی است که از هر دو پروتکل HTTP(S) و SOCKS5 پشتیبانی می‌کند. می‌توانید با استفاده از هر برنامه‌ای که از پروکسی‌های HTTP یا SOCKS پشتیبانی می‌کند، به این پورت متصل شوید، به عنوان مثال:

پوسته
$ curl -x socks5h://127.0.0.1:7890 -v http://connect.rom.miui.com/generate_204
*   Trying 127.0.0.1:7890...
* SOCKS5 connect to connect.rom.miui.com:80 (remotely resolved)
* SOCKS5 request granted.
* Connected to (nil) (127.0.0.1) port 7890 (#0)
> GET /generate_204 HTTP/1.1
> Host: connect.rom.miui.com
> User-Agent: curl/7.81.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 204 No Content
< Date: Thu, 11 May 2023 06:18:22 GMT
< Connection: keep-alive
< Content-Type: text/plain
<
* Connection #0 to host (nil) left intact
ریدایرکت و تی‌پروکسی
ریدایرکت و تی‌پروکسی دو روش مختلف برای پیاده‌سازی پروکسی شفاف هستند که هر دو توسط کلش پشتیبانی می‌شوند.

خروجی
کلش چندین نوع سرویس خروجی ارائه می‌دهد. هر نوع ویژگی‌ها و موارد استفاده خاص خود را دارد. در این صفحه، ویژگی‌های کلی هر نوع و همچنین نحوه استفاده و پیکربندی آنها را معرفی خواهیم کرد.

پروکسی‌ها، گره‌های پروکسی
شدوساکس
شدوساکس آر
ومس
جوراب5
اچ‌تی‌پی
اسنل
تروجان
گروه‌های پروکسی
رله
تست تأخیر url-test
تست کاربردپذیری جایگزین
متعادل‌سازی بار
انتخاب (انتخاب دستی)
ارائه دهندگان پروکسی
پروکسی‌ها، گره‌های پروکسی
پروکسی‌ها مقصدهای خروجی هستند که می‌توانید آنها را پیکربندی کنید. درست مانند سرورهای پروکسی، شما مقصد بسته‌های داده خود را در اینجا تعریف می‌کنید.

شدوساکس
کلش از روش‌های رمزگذاری Shadowsocks زیر پشتیبانی می‌کند:

سری	روش رمزگذاری
AEAD	aes-128-gcm، aes-192-gcm، aes-256-gcm، chacha20-ietf-poly1305، xchacha20-ietf-poly1305
فلوسیتومتری	aes-128-cfb، aes-192-cfb، aes-256-cfb، rc4-md5، chacha20-ietf، xchacha20
بلوک	aes-128-ctr، aes-192-ctr، aes-256-ctr
obfsعلاوه بر این، کلش از افزونه محبوب Shadowsocks نیز پشتیبانی می‌کند v2ray-plugin.


اساسی

مبهم‌ها

ws (سوکت وب)
یامل
- name: "ss1"
  type: ss
  # interface-name: eth0
  # routing-mark: 1234
  server: server
  port: 443
  cipher: chacha20-ietf-poly1305
  password: "password"
  # udp: true
شدوساکس آر
کلش همچنین از پروتکل بدنام ضد سانسور ShadowsocksR پشتیبانی می‌کند.

روش‌های رمزگذاری زیر توسط ShadowsocksR پشتیبانی می‌شوند:

سری	روش رمزگذاری
فلوسیتومتری	aes-128-cfb، aes-192-cfb، aes-256-cfb، rc4-md5، chacha20-ietf، xchacha20
روش‌های مبهم‌سازی پشتیبانی‌شده:

ساده
http_simple
http_post
تصادفی_هد
tls1.2_ticket_auth
tls1.2_ticket_fastauth
پروتکل‌های پشتیبانی‌شده:

منشأ
auth_sha1_v4
auth_aes128_md5
auth_aes128_sha1
auth_chain_a
auth_chain_b
یامل
- name: "ssr"
  type: ssr
  # interface-name: eth0
  # routing-mark: 1234
  server: server
  port: 443
  cipher: chacha20-ietf
  password: "password"
  obfs: tls1.2_ticket_auth
  protocol: auth_sha1_v4
  # obfs-param: domain.tld
  # protocol-param: "#"
  # udp: true
ومس
کلش از روش‌های رمزگذاری Vmess زیر پشتیبانی می‌کند:

خودکار
aes-128-gcm
chacha20-poly1305
هیچ کدام

اساسی

اچ‌تی‌پی

HTTP/2

gRPC
یامل
- name: "vmess"
  type: vmess
  # interface-name: eth0
  # routing-mark: 1234
  server: server
  port: 443
  uuid: uuid
  alterId: 32
  cipher: auto
  # udp: true
  # tls: true
  # skip-cert-verify: true
  # servername: example.com # 优先于 wss 主机
  # network: ws
  # ws-opts:
  #   path: /path
  #   headers:
  #     Host: v2ray.com
  #   max-early-data: 2048
  #   early-data-header-name: Sec-WebSocket-Protocol
جوراب5
علاوه بر این، کلش از پروکسی‌های Socks5 نیز پشتیبانی می‌کند.

یامل
- name: "socks"
  type: socks5
  # interface-name: eth0
  # routing-mark: 1234
  server: server
  port: 443
  # username: username
  # password: password
  # tls: true
  # skip-cert-verify: true
  # udp: true
اچ‌تی‌پی
کلش همچنین از پروکسی‌های HTTP پشتیبانی می‌کند:


اچ‌تی‌پی

HTTPS
یامل
- name: "http"
  type: http
  # interface-name: eth0
  # routing-mark: 1234
  server: server
  port: 443
  # username: username
  # password: password
اسنل
به عنوان یک پروتکل ضد سانسور اختیاری، کلش پشتیبانی از اسنل را نیز در خود جای داده است.

یامل
# 暂不支持 UDP
- name: "snell"
  type: snell
  # interface-name: eth0
  # routing-mark: 1234
  server: server
  port: 44046
  psk: yourpsk
  # version: 2
  # obfs-opts:
    # mode: http # or tls
    # host: bing.com
تروجان
کلش از پروتکل محبوب تروجان به صورت داخلی پشتیبانی می‌کند:


اساسی

gRPC

ws (سوکت وب)
یامل
- name: "trojan"
  type: trojan
  # interface-name: eth0
  # routing-mark: 1234
  server: server
  port: 443
  password: yourpsk
  # udp: true
  # sni: example.com # aka server name
  # alpn:
  #   - h2
  #   - http/1.1
  # skip-cert-verify: true
گروه‌های پروکسی
گروه‌های پروکسی برای توزیع درخواست‌های عبور داده شده از طریق قوانین مطابق با سیاست‌های مختلف استفاده می‌شوند. آن‌ها می‌توانند مستقیماً توسط قوانین یا توسط سایر گروه‌های سیاستی ارجاع داده شوند، در حالی که گروه سیاستی سطح بالا توسط قوانین ارجاع داده می‌شود.

رله
درخواست به ترتیب از طریق سرورهای پروکسی مشخص شده ارسال خواهد شد. در حال حاضر از UDP پشتیبانی نمی‌شود. سرور پروکسی مشخص شده نباید حاوی رله دیگری باشد.

تست تأخیر url-test
کلش به صورت دوره‌ای درخواست‌های HTTP HEAD را از طریق یک URL مشخص به سرورهای پروکسی موجود در لیست ارسال می‌کند تا میزان تأخیر هر سرور پروکسی را آزمایش کند . حداکثر تحمل، فاصله زمانی آزمایش و URL هدف قابل تنظیم هستند.

تست کاربردپذیری جایگزین
کلش به صورت دوره‌ای درخواست‌های HTTP HEAD را از طریق یک URL مشخص به سرورهای پروکسی موجود در لیست ارسال می‌کند تا در دسترس بودن هر سرور پروکسی را آزمایش کند . اولین سرور موجود استفاده خواهد شد.

متعادل‌سازی بار
درخواست‌هایی که eTLD+1 یکسانی دارند، از پروکسی سرور یکسانی استفاده خواهند کرد.

انتخاب (انتخاب دستی)
کلش به طور پیش‌فرض هنگام راه‌اندازی از اولین سرور پروکسی در گروه سیاست استفاده می‌کند. کاربران می‌توانند با استفاده از RESTful API، سرور پروکسی مورد نظر خود را انتخاب کنند. در این حالت، می‌توانید سرور را در پیکربندی به صورت دستی تعریف کنید یا به صورت پویا با استفاده از مجموعه پروکسی Proxy Providers سرورها را اضافه کنید .

صرف نظر از روش، گاهی اوقات می‌توانید از اتصال مستقیم برای مسیریابی بسته‌ها نیز استفاده کنید. در این حالت، می‌توانید DIRECTاز اتصال مستقیم خروجی استفاده کنید.

برای استفاده از رابط‌های شبکه مختلف، باید DIRECTاز یک گروه سیاست‌گذاری که شامل اتصالات خروجی مستقیم است استفاده کنید و interface-nameگزینه‌ها را پیکربندی کنید.

یامل
- name: "My Wireguard Outbound"
  type: select
  interface-name: wg0
  proxies: [ 'DIRECT' ]
ارائه دهندگان پروکسی
مجموعه‌های پروکسی به کاربران این امکان را می‌دهند که به جای کدگذاری سخت (hardcoded) فهرستی از سرورهای پروکسی در یک فایل پیکربندی، آنها را به صورت پویا بارگذاری کنند. در حال حاضر، دو نوع مجموعه پروکسی وجود دارد که می‌توانند فهرست سرورها را بارگذاری کنند:

httpکلش در هنگام شروع، فهرستی از سرورها را از URL مشخص شده بارگذاری می‌کند. اگر intervalاین گزینه تنظیم شده باشد، کلش به صورت دوره‌ای فهرست سرورها را از یک مکان دوردست دریافت می‌کند.
fileکلش در هنگام راه‌اندازی، فهرستی از سرورها را از محل فایل مشخص‌شده بارگذاری می‌کند.
بررسی‌های سلامت در هر دو حالت موجود است و با بررسی‌های گروه سیاست یکسان است fallback. قالب پیکربندی فایل لیست سرور نیز دقیقاً مشابه فایل پیکربندی اصلی است:


پیکربندی.yaml

تست.yaml
یامل
proxy-providers:
  provider1:
    type: http
    url: "url"
    interval: 3600
    path: ./provider1.yaml
    # filter: 'a|b' # golang regex 正则表达式
    health-check:
      enable: true
      interval: 600
      # lazy: true
      url: http://www.gstatic.com/generate_204
  test:
    type: file
    path: /test.yaml
    health-check:
      enable: true
      interval: 36000
      url: http://www.gstatic.com/generate_204
صفحه قبلی
ورودی


قوانین
در راهنمای شروع سریع ، اصول اولیه تطبیق مبتنی بر قانون در کلش را معرفی کردیم. در این فصل، تمام انواع قوانین موجود در آخرین نسخه کلش را معرفی خواهیم کرد.

متن
# 类型,参数,策略(,no-resolve)
TYPE,ARGUMENT,POLICY(,no-resolve)
no-resolveاین گزینه اختیاری است و برای رد کردن DNS resolution برای قوانین استفاده می‌شود. این گزینه زمانی مفید است که می‌خواهید از قوانین GEOIP`.id`، IP-CIDR` IP-CIDR6.ip` و `.id` استفاده کنید، اما نمی‌خواهید بلافاصله نام دامنه را به یک آدرس IP resolve کنید.SCRIPT

استراتژی
نوع قانون
دامنه
پسوند دامنه
کلمات کلیدی دامنه
موقعیت جغرافیایی (کد کشور)
محدوده آدرس IPv4 با IP-CIDR
محدوده آدرس IPv6 از IP-CIDR6
آدرس محدوده IP منبع SRC-IP-CIDR
پورت منبع SRC-PORT
پورت هدف DST-PORT
نام فرآیند: نام فرآیند منبع
مسیر فرآیند: مسیر فرآیند منبع
تنظیم IP ست
مجموعه قوانین (مجموعه قوانین)
اسکریپت
مطابقت (همه را مطابقت دهید)
استراتژی
در حال حاضر چهار نوع استراتژی وجود دارد که از جمله آنها عبارتند از:

مستقیم: interface-nameمستقیماً به هدف متصل می‌شود (بدون مراجعه به جدول مسیریابی سیستم).
رد کردن: بسته‌های داده را دور بریزید
پروکسی: بسته‌های داده را به سرور پروکسی مشخص‌شده هدایت می‌کند.
گروه پروکسی: بسته‌ها را به گروه سیاست مشخص‌شده هدایت می‌کند.
نوع قانون
بخش‌های زیر هر نوع قانون و نحوه استفاده از آن را شرح می‌دهند:

دامنه
DOMAIN,www.google.com,policyمسیریابی www.google.comبه policy.

پسوند دامنه
DOMAIN-SUFFIX,youtube.com,policyهر نام دامنه‌ای که به ختم می‌شود youtube.comرا مسیریابی کنید policy.

در این حالت، www.youtube.comهر دو و foo.bar.youtube.comبه هدایت خواهند شد policy.

کلمات کلیدی دامنه
DOMAIN-KEYWORD,google,policyهر googleدامنه‌ای که حاوی کلمه کلیدی باشد را به [دامنه مشخص شده policy] هدایت کنید.

در این حالت، یا [مسیر ۱] www.google.comیا [ googleapis.comمسیر ۲] به [مسیر ۳] مسیریابی خواهند شد policy.

موقعیت جغرافیایی (کد کشور)
از قوانین GEOIP برای مسیریابی بسته‌های داده بر اساس کد کشور آدرس IP مقصد استفاده می‌شود . Clash از پایگاه داده MaxMind GeoLite2 برای پیاده‌سازی این قابلیت استفاده می‌کند.

هشدار

هنگام استفاده از این قانون، Clash نام دامنه را به یک آدرس IP تبدیل می‌کند و سپس کد کشور آدرس IP را جستجو می‌کند. برای صرف نظر کردن از DNS resolution، از no-resolveگزینه‌ی

GEOIP,CN,policyهر بسته داده‌ای که آدرس IP مقصد آن در چین است را به [مقصد مناسب] هدایت کنید policy.

محدوده آدرس IPv4 با IP-CIDR
از قوانین IP-CIDR برای مسیریابی بسته‌های داده بر اساس آدرس IPv4 مقصد بسته‌ها استفاده می‌شود .

هشدار

هنگام استفاده از این قانون، Clash نام دامنه را به یک آدرس IPv4 تبدیل می‌کند. برای صرف نظر کردن از تبدیل DNS، از no-resolveگزینه‌ی

IP-CIDR,127.0.0.0/8,DIRECTهر 127.0.0.0/8بسته‌ای که به مقصد آدرس IP است را به [address] هدایت کنید DIRECT.

محدوده آدرس IPv6 از IP-CIDR6
از قوانین IP-CIDR6 برای مسیریابی بسته‌های داده بر اساس آدرس IPv6 مقصد بسته‌ها استفاده می‌شود .

هشدار

هنگام استفاده از این قانون، Clash نام دامنه را به آدرس IPv6 تبدیل می‌کند. برای صرف نظر کردن از تبدیل DNS، از no-resolveگزینه‌ی

IP-CIDR6,2620:0:2d0:200::7/32,policyهر 2620:0:2d0:200::7/32بسته‌ای که به مقصد آدرس IP است را به [address] هدایت کنید policy.

آدرس محدوده IP منبع SRC-IP-CIDR
قوانین SRC-IP-CIDR برای مسیریابی بسته‌های داده بر اساس آدرس IPv4 منبع آنها استفاده می‌شوند .

SRC-IP-CIDR,192.168.1.201/32,DIRECT192.168.1.201/32هر بسته‌ای را که آدرس IP منبع آن مشخص شده است، به [address] مسیریابی کنید DIRECT.

پورت منبع SRC-PORT
از قانون SRC-PORT برای مسیریابی بسته‌های داده بر اساس پورت مبدا آنها استفاده می‌شود.

SRC-PORT,80,policy80هر بسته‌ای را که دارای پورت مبدا است به [نام پورت policy] هدایت کنید.

پورت هدف DST-PORT
از قانون DST-PORT برای مسیریابی بسته‌های داده بر اساس پورت مقصد آنها استفاده می‌شود.

DST-PORT,80,policyهر 80بسته‌ای که مقصدش پورت ۰ است را به پورت policy۰ هدایت کنید.

نام فرآیند: نام فرآیند منبع
قانون PROCESS-NAME برای مسیریابی بسته‌های داده بر اساس نام فرآیندی که آنها را ارسال کرده است، استفاده می‌شود.

هشدار

در حال حاضر، این برنامه فقط از macOS، لینوکس، FreeBSD و ویندوز پشتیبانی می‌کند.

PROCESS-NAME,nc,DIRECTهر ncبسته‌ای را از فرآیند به [ مسیر مناسب DIRECT] هدایت کنید.

مسیر فرآیند: مسیر فرآیند منبع
قانون PROCESS-PATH برای مسیریابی بسته‌های داده بر اساس مسیر فرآیندی که بسته‌های داده از آن ارسال می‌شوند، استفاده می‌شود.

هشدار

در حال حاضر، این برنامه فقط از macOS، لینوکس، FreeBSD و ویندوز پشتیبانی می‌کند.

PROCESS-PATH,/usr/local/bin/nc,DIRECTهر /usr/local/bin/ncبسته‌ای که از فرآیند در مسیر به سرچشمه می‌گیرد را مسیریابی کنید DIRECT.

تنظیم IP ست
قوانین IPSET برای تطبیق و مسیریابی بسته‌ها بر اساس مجموعه‌ای از آدرس‌های IP استفاده می‌شوند. طبق وب‌سایت رسمی IPSET :

مجموعه‌های IP چارچوبی در هسته لینوکس هستند که می‌توانند از طریق برنامه ipset مدیریت شوند. بسته به نوع، مجموعه‌های IP می‌توانند آدرس‌های IP، شبکه‌ها، شماره پورت‌های (TCP/UDP)، آدرس‌های MAC، نام‌های رابط یا ترکیبی از آنها را به نحوی ذخیره کنند تا تطبیق سریع ورودی‌ها در مجموعه تضمین شود.

بنابراین، این ویژگی فقط روی لینوکس کار می‌کند و نیاز به نصب دارد ipset.

هشدار

هنگام استفاده از این قانون، Clash نام دامنه را برای به دست آوردن آدرس IP تجزیه و تحلیل می‌کند و سپس بررسی می‌کند که آیا آدرس IP در مجموعه IP وجود دارد یا خیر. برای رد کردن تجزیه و تحلیل DNS، no-resolveاز گزینه استفاده کنید.

IPSET,chnroute,policychnrouteبسته‌ها را به هر آدرس IP مقصد در مجموعه IP هدایت می‌کند policy.

مجموعه قوانین (مجموعه قوانین)
اطلاعات

این قابلیت فقط در نسخه پریمیوم (Premium) موجود است .

قوانین RULE-SET برای مسیریابی بسته‌ها بر اساس نتایج مجموعه قوانین Rule Providers استفاده می‌شوند . وقتی Clash از این قانون استفاده می‌کند، قوانین را از مجموعه قوانین Rule Providers مشخص شده بارگذاری می‌کند و سپس بسته‌ها را با قوانین مطابقت می‌دهد. اگر یک بسته با هر قانونی مطابقت داشته باشد، بسته به سیاست مشخص شده مسیریابی می‌شود. در غیر این صورت، از آن قانون صرف نظر می‌شود.

هشدار

هنگام استفاده از RULE-SET، اگر نوع مجموعه قانون IPCIDR باشد، Clash نام دامنه را برای به دست آوردن آدرس IP تجزیه و تحلیل می‌کند. برای صرف نظر کردن از تجزیه و تحلیل DNS، no-resolveاز این گزینه استفاده کنید.

RULE-SET,my-rule-provider,DIRECTاز my-rule-providerبارگیری همه قوانین

اسکریپت
اطلاعات

این قابلیت فقط در نسخه پریمیوم (Premium) موجود است .

قوانین SCRIPT برای مسیریابی بسته‌ها بر اساس نتایج یک اسکریپت استفاده می‌شوند. وقتی Clash از این قانون استفاده می‌کند، اسکریپت مشخص شده را اجرا می‌کند و سپس بسته‌ها را به خروجی اسکریپت هدایت می‌کند.

هشدار

هنگام استفاده از SCRIPT، Clash نام دامنه را برای به دست آوردن آدرس IP تجزیه و تحلیل می‌کند. برای صرف نظر کردن از تجزیه و تحلیل DNS، از no-resolveاین گزینه استفاده کنید.

SCRIPT,script-path,DIRECTبسته‌ها را به script-pathخروجی اسکریپت هدایت کنید.

مطابقت (همه را مطابقت دهید)
از قانون MATCH برای مسیریابی بسته‌های باقیمانده استفاده می‌شود. این قانون الزامی است و معمولاً به عنوان آخرین قانون استفاده می‌شود.

MATCH,policyبسته‌های باقیمانده به policy... هدایت می‌شوند.
صفحه
کلش دی‌ان‌اس
از آنجا که برخی از بخش‌های کلش در لایه ۳ (لایه شبکه) عمل می‌کنند، نام دامنه بسته‌های داده آن قابل دستیابی نیست و مسیریابی مبتنی بر قانون را غیرممکن می‌سازد.

وارد fake-ip شوید : این پروتکل از مسیریابی مبتنی بر قانون پشتیبانی می‌کند، تأثیر حملات DNS Poisoning را به حداقل می‌رساند و عملکرد شبکه را، گاهی اوقات به طور قابل توجهی، بهبود می‌بخشد.

آی‌پی جعلی
مفهوم «آی‌پی جعلی» از RFC 3089 سرچشمه می‌گیرد .

یک آدرس «IP جعلی» به عنوان کلمه کلیدی برای جستجوی اطلاعات «FQDN» مربوطه استفاده شد.

CIDR پیش‌فرض برای مجموعه آدرس‌های fake-ip، 198.18.0.1/16یک فضای آدرس IPv4 رزرو شده است که می‌توان dns.fake-ip-rangeآن را در [configuration settings] تغییر داد.

وقتی یک درخواست DNS به Clash DNS ارسال می‌شود، هسته Clash با مدیریت نگاشت داخلی نام‌های دامنه و آدرس‌های IP جعلی آنها، یک آدرس IP جعلی رایگان از مجموعه اختصاص می‌دهد.

http://google.comبه عنوان مثال، دسترسی از طریق مرورگر را در نظر بگیرید .

google.comآدرس IP درخواست شده توسط مرورگر از Clash DNS

کلش نگاشت داخلی را بررسی کرده و برمی‌گرداند.198.18.1.5

مرورگر یک درخواست HTTP به پورت ارسال می‌کند 198.18.1.5.80/tcp

وقتی 198.18.1.5یک بسته داده ورودی دریافت می‌شود، Clash نقشه داخلی خود را بررسی می‌کند و متوجه می‌شود که کلاینت در واقع در حال ارسال google.comیک بسته داده به [محل هدف] است.

بسته به قوانین:

کلش فقط می‌تواند نام دامنه را به یک پروکسی خروجی مانند SOCKS5 یا Shadowsocks ارسال کند و با سرور پروکسی ارتباط برقرار کند.

از طرف دیگر، Clash ممکن است SCRIPTاز قوانین GEOIPیا IP-CIDRجستجوی اتصال مستقیم DIRECT برای جستجوی google.comآدرس IP واقعی استفاده کند.

از آنجایی که این مفهوم گیج‌کننده است، من از دسترسی از طریق cURL http://google.comبه عنوان مثال استفاده می‌کنم:

متن
$ curl -v http://google.com
<---- cURL 向您的系统 DNS (Clash) 询问 google.com 的 IP 地址
----> Clash 决定使用 198.18.1.70 作为 google.com 的 IP 地址, 并记住它
*   Trying 198.18.1.70:80...
<---- cURL 连接到 198.18.1.70 tcp/80
----> Clash 将立即接受连接, 并且..
* Connected to google.com (198.18.1.70) port 80 (#0)
----> Clash 在其内存中查找到 198.18.1.70 对应于 google.com
----> Clash 查询对应的规则, 并通过匹配的出口发送数据包
> GET / HTTP/1.1
> Host: google.com
> User-Agent: curl/8.0.1
> Accept: */*
>
< HTTP/1.1 301 Moved Permanently
< Location: http://www.google.com/
< Content-Type: text/html; charset=UTF-8
< Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-ahELFt78xOoxhySY2lQ34A' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
< Date: Thu, 11 May 2023 06:52:19 GMT
< Expires: Sat, 10 Jun 2023 06:52:19 GMT
< Cache-Control: public, max-age=2592000
< Server: gws
< Content-Length: 219
< X-XSS-Protection: 0
< X-Frame-Options: SAMEORIGIN
<
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
* Connection #0 to host google.com left intact
صفحه قبلی
قوانین



Clash Premium قابلیت‌های اسکریپت‌نویسی مبتنی بر پایتون ۳ را پیاده‌سازی می‌کند و به کاربران اجازه می‌دهد تا به صورت پویا و انعطاف‌پذیر، استراتژی‌های مربوط به بسته‌های داده را انتخاب کنند.

شما می‌توانید کل موتور تطبیق قانون را با استفاده از یک اسکریپت پایتون کنترل کنید، یا می‌توانید میانبرهایی تعریف کنید و آنها را همراه با قوانین معمولی استفاده کنید. این صفحه ویژگی اول را شرح می‌دهد؛ برای مورد دوم، به میانبرهای اسکریپت مراجعه کنید .

کنترل کل موتور تطبیق قانون
یامل
mode: Script

# https://lancellc.gitbook.io/clash/clash-config-file/script
script:
  code: |
    def main(ctx, metadata):
      ip = metadata["dst_ip"] = ctx.resolve_ip(metadata["host"])
      if ip == "":
        return "DIRECT"

      code = ctx.geoip(ip)
      if code == "LAN" or code == "CN":
        return "DIRECT"

      return "Proxy" # default policy for requests which are not matched by any other script
اگر می‌خواهید از قوانین IP (مثل IP-CIDR، GEOIP و غیره) استفاده کنید، ابتدا باید آدرس‌های IP را به صورت دستی حل کنید و آنها را به فراداده اختصاص دهید.

پایتون
def main(ctx, metadata):
    # ctx.rule_providers["geoip"].match(metadata) return false

    ip = ctx.resolve_ip(metadata["host"])
    if ip == "":
        return "DIRECT"
    metadata["dst_ip"] = ip

    # ctx.rule_providers["iprule"].match(metadata) return true

    return "Proxy"
تعاریف رابط برای فراداده و متن:

تی اس
interface Metadata {
  type: string // socks5、http
  network: string // tcp
  host: string
  src_ip: string
  src_port: string
  dst_ip: string
  dst_port: string
  inbound_port: number
}

interface Context {
  resolve_ip: (host: string) => string // ip string
  resolve_process_name: (metadata: Metadata) => string
  resolve_process_path: (metadata: Metadata) => string
  geoip: (ip: string) => string // country code
  log: (log: string) => void
  proxy_providers: Record<string, Array<{ name: string, alive: boolean, delay: number }>>
  rule_providers: Record<string, { match: (metadata: Metadata) => boolean }>
}
صفحه قبلی
تابع: ارائه دهندگان قانون (مجموعه قوانین)

یپت
Clash Premium قابلیت‌های اسکریپت‌نویسی مبتنی بر پایتون ۳ را پیاده‌سازی می‌کند و به کاربران اجازه می‌دهد تا به صورت پویا و انعطاف‌پذیر، استراتژی‌های مربوط به بسته‌های داده را انتخاب کنند.

شما می‌توانید کل موتور تطبیق قانون را با استفاده از یک اسکریپت پایتون کنترل کنید، یا می‌توانید میانبرهایی تعریف کنید و آنها را همراه با قوانین معمولی استفاده کنید. این صفحه به عملکرد دوم اشاره دارد. برای مورد اول، به بخش اسکریپت‌ها مراجعه کنید .

این ویژگی rulesامکان استفاده از اسکریپت‌ها را در حالت SCRIPT فراهم می‌کند. به طور پیش‌فرض، تجزیه و تحلیل DNS در قوانین SCRIPT انجام می‌شود. می‌توانید `--prevent-resolve` را به قانون اضافه کنید no-resolveتا از تجزیه و تحلیل جلوگیری شود. (به عنوان مثال: `--prevent-resolve-by -rules` SCRIPT,quic,DIRECT,no-resolve)

یامل
mode: Rule

script:
  engine: expr # or starlark (10x to 20x slower)
  shortcuts:
    quic: network == 'udp' and dst_port == 443
    curl: resolve_process_name() == 'curl'
    # curl: resolve_process_path() == '/usr/bin/curl'

rules:
  - SCRIPT,quic,REJECT
موتور ارزیابی
Expr، به عنوان موتور پیش‌فرض برای میانبرهای اسکریپت، در مقایسه با Starlark، بهبود عملکردی ۱۰ تا ۲۰ برابری ارائه می‌دهد.

استارلارک یک زبان پیکربندی شبیه به پایتون است که می‌توانید از آن برای میانبرهای اسکریپت نیز استفاده کنید.

متغیر
شبکه: رشته
نوع: رشته
src_ip: رشته
dst_ip: رشته
پورت src: uint16
پورت dst: uint16
پورت ورودی: uint16
میزبان: رشته
مسیر_پردازش: رشته
هشدار

process_pathاستارلارک در حال حاضر شامل متغیرها نمی‌شود .

تابع
تی اس
type resolve_ip = (host: string) => string // ip string
type in_cidr = (ip: string, cidr: string) => boolean // ip in cidr
type in_ipset = (name: string, ip: string) => boolean // ip in ipset
type geoip = (ip: string) => string // country code
type match_provider = (name: string) => boolean // in rule provider
type resolve_process_name = () => string // find process name (curl .e.g)
type resolve_process_path = () => string // find process path (/usr/bin/curl .e.g)
صفحه قبلی
عملکرد: اسکریپت
صفحه

از آنجا که Wireguard به پشته TCP/IP در gvisor متکی است، در حال حاضر فقط در هسته Premium در دسترس است.

یامل
proxies:
  - name: "wg"
    type: wireguard
    server: 127.0.0.1
    port: 443
    ip: 172.16.0.2
    # ipv6: your_ipv6
    private-key: eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
    public-key: Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=
    # preshared-key: base64
    # remote-dns-resolve: true # 远程解析 DNS, 使用 `dns` 字段, 默认为 true
    # dns: [1.1.1.1, 8.8.8.8]
    # mtu: 1420
    udp: true
عملکرد
https://github.com/Dreamacro/clash-tracing

یامل
profile:
    tracing: true
صفحه قبلی

 کاربری گرافیکی Clash شخص ثالث بر اساس این قابلیت ساخته شده‌اند. external-controllerاین ویژگی با مشخص کردن آدرس در فایل پیکربندی فعال می‌شود.

صدور گواهینامه
کنترل‌کننده خارجی [این] را Bearer Tokensبه عنوان روش احراز هویت دسترسی می‌پذیرد.
Authorization: Bearer <Your Secret>از آن به عنوان هدر درخواست برای ارسال اعتبارنامه‌ها استفاده کنید .
مستندات RESTful API
ورود به سیستم
/logs
روش:GET
مسیر کامل:GET /logs
توضیحات: دریافت گزارش‌های بلادرنگ
جریان
/traffic
روش:GET
مسیر کامل:GET /traffic
توضیحات: دریافت داده‌های ترافیکی در لحظه
نسخه
/version
روش:GET
مسیر کامل:GET /version
توضیحات: دریافت نسخه کلش
پیکربندی
/configs
روش:GET

مسیر کامل:GET /configs
توضیحات: دریافت پیکربندی اولیه
روش:PUT

مسیر کامل:PUT /configs
توضیحات: فایل پیکربندی را دوباره بارگذاری کنید
روش:PATCH

مسیر کامل:PATCH /configs
شرح: اصلاح تدریجی پیکربندی
گره
/proxies

روش:GET
مسیر کامل:GET /proxies
توضیحات: بازیابی تمام اطلاعات گره
/proxies/:name

روش:GET

مسیر کامل:GET /proxies/:name
توضیحات: بازیابی اطلاعات مربوط به یک گره مشخص شده.
روش:PUT

مسیر کامل:PUT /proxies/:name
توضیحات: گره انتخاب شده را در انتخابگر تغییر وضعیت دهید.
/proxies/:name/delay

روش:GET
مسیر کامل:GET /proxies/:name/delay
توضیحات: بازیابی اطلاعات تست تأخیر برای یک گره مشخص شده.
قاعده
/rules
روش:GET
مسیر کامل:GET /rules
توضیحات: بازیابی اطلاعات قوانین
اتصال
/connections

روش:GET

مسیر کامل:GET /connections
توضیحات: بازیابی اطلاعات اتصال
روش:DELETE

مسیر کامل:DELETE /connections
توضیحات: تمام اتصالات را ببندید
/connections/:id

روش:DELETE
مسیر کامل:DELETE /connections/:id
توضیحات: اتصال مشخص شده را ببندید
مجموعه پروکسی
/providers/proxies

روش:GET
مسیر کامل:GET /providers/proxies
توضیحات: اطلاعات پروکسی را برای همه مجموعه‌های پروکسی بازیابی می‌کند.
/providers/proxies/:name

روش:GET

مسیر کامل:GET /providers/proxies/:name
توضیحات: اطلاعات پروکسی را برای یک مجموعه پروکسی مشخص شده بازیابی می‌کند.
روش:PUT

مسیر کامل:PUT /providers/proxies/:name
توضیحات: تغییر مجموعه پروکسی مشخص شده.
/providers/proxies/:name/healthcheck

روش:GET
مسیر کامل:GET /providers/proxies/:name/healthcheck
توضیحات: اطلاعات پروکسی را برای یک مجموعه پروکسی مشخص شده بازیابی می‌کند.
جستجوی DNS
/dns/query
روش:GET

مسیر کامل:GET /dns/query?name={name}[&type={type}]

توضیحات: داده‌های پرس‌وجوی DNS را برای یک نام و نوع دامنه مشخص‌شده بازیابی می‌کند.

پارامتر:

name(الزامی): نام دامنه مورد نظر برای جستجو
type(اختیاری): نوع رکورد DNS برای جستجو (مثلاً A، MX، CNAME و غیره). اگر ارائه نشود، به طور پیش‌فرض روی این تنظیم می‌شود A.
مثال:GET /dns/query?name=example.com&type=A

صفحه قبلی
با فرض اینکه کرنل شما از Wireguard پشتیبانی می‌کند و شما آن را فعال کرده‌اید، Tableاین گزینه می‌تواند از بازنویسی مسیر پیش‌فرض توسط wg-quick جلوگیری کند.

برای مثال wg0.conf:

این
[Interface]
PrivateKey = ...
Address = 172.16.0.1/32
MTU = ...
Table = off
PostUp = ip rule add from 172.16.0.1/32 table 6666

[Peer]
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
PublicKey = ...
Endpoint = ...
سپس در Clash شما فقط به یک گروه سیاست DIRECT نیاز دارید که شامل یک رابط خروجی مشخص شده است:

یامل
proxy-groups:
  - name: Wireguard
    type: select
    interface-name: wg0
    proxies:
      - DIRECT
rules:
  - DOMAIN,google.com,Wireguard
این معمولاً منجر به عملکرد بهتری نسبت به کلاینت Wireguard فضای کاربری خود Clash می‌شود که در هسته پشتیبانی می‌شود.

