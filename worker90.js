// Trojan-worker + simple panel + auth (merged, spacing fixed)
// Default password (change if you want)
const PASSWORD = "12345678";

// منابع اصلی (sub links) — می‌تونی این آرایه را ویرایش یا اضافه کنی
const subLinks = [
  "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/ws_tls/proxies/wstls",
  "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",
  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/refs/heads/main/protocols/trojan",
  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/refs/heads/main/protocols/vmess",
  "https://sab-poro1383.ahsan-tepo1383online.workers.dev/?file=config.txt",
  "https://sab-vip10.ahsan-tepo1383online.workers.dev/config1.txt",
  "https://raw.githubusercontent.com/tepo18/online-sshmax98/main/config.txt",
  "https://raw.githubusercontent.com/tepo18/reza-shah1320/main/vip20.txt",
  "https://almasi-9025.batool-sogeli.workers.dev/arista",
  "https://raw.githubusercontent.com/tepo18/reza-shah1320/main/config.txt",
  // منابع اضافی شما
  "https://raw.githubusercontent.com/tepo18/online-sshmax98/main/config3.txt",
  "https://raw.githubusercontent.com/tepo18/sab-vip15606/main/config.txt",
  "https://ahsan-tepo1383.almasi-ali98.workers.dev/config3.txt",
  "https://ahsan-tepo1383.almasi-ali98.workers.dev/config5.txt",
  "https://ahsan-tepo1383.almasi-ali98.workers.dev/config.txt",
  "https://sab-vip10.ahsan-tepo1383online.workers.dev/config.txt",
  "https://sab-vip10.ahsan-tepo1383online.workers.dev/config4.txt"
];

// پارامترهای پنل / گزینه‌های خروجی که UI انتظار دارد
const outputOptions = [50, 500, 1500, 3000]; // 3000 اضافه شد، 'all' به صورت نرمال همه خروجی‌هاست

// توزیع منابع (rotating chunk) — از منطق سازنده استفاده شده
const sources = subLinks.slice();
const chunkSize = Math.max(1, Math.ceil(sources.length / 3));
let refreshIndex = 0;
function getCurrentSources() {
  const start = refreshIndex * chunkSize;
  const end = start + chunkSize;
  const chunk = sources.slice(start, end);
  refreshIndex = (refreshIndex + 1) % 3;
  return chunk.length ? chunk : sources.slice(0, chunkSize);
}

// کمکی‌ها
function normalizeLine(line) {
  return (line || "").trim().toLowerCase().replace(/\s+/g, "");
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp('(^|; )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}

function setCookieHeader(name, value, maxAgeSeconds = 3600) {
  return `${name}=${value}; Path=/; HttpOnly; Max-Age=${maxAgeSeconds}; SameSite=Lax`;
}

function parseFormUrlencoded(bodyText) {
  const params = new URLSearchParams(bodyText);
  return Object.fromEntries(params.entries());
}

function shouldSkipHost(host) {
  if (!host) return true;
  host = host.toLowerCase();
  return host.includes("workers.dev") || host.includes("pages.dev");
}

function getRandomItems(arr, count) {
  const copy = arr.slice();
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, count);
}

function isIp(str) {
  if (!str) return false;
  const regex = /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){3}$/;
  if (!regex.test(str)) return false;
  const parts = str.split('.');
  if (parts[3] === '0') return false;
  return true;
}

// HTML صفحهٔ ورود (ساده، وسط‌چین، فونت خوانا)
function htmlLoginPage() {
  return `<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ورود به پنل</title>
<style>
  html,body{height:100%;margin:0;font-family:Arial,Helvetica,sans-serif;background:#f7fbff}
  .box{width:360px;background:#fff;padding:28px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.06);margin:auto;display:flex;flex-direction:column;align-items:center}
  h1{font-size:20px;margin:0 0 14px;color:#111}
  input[type=password]{width:100%;padding:12px 10px;font-size:16px;border:1px solid #e6e9ef;border-radius:8px;margin-bottom:12px;box-sizing:border-box}
  button{width:100%;padding:11px;font-size:16px;border-radius:8px;border:0;background:#0b84ff;color:#fff;cursor:pointer}
  .hint{font-size:13px;color:#666;margin-top:10px}
  body{display:flex;align-items:center;justify-content:center}
  .small{font-size:12px;color:#999;margin-top:8px}
</style>
</head>
<body>
<form class="box" method="POST" action="/" autocomplete="off">
  <h1>ورود به پنل Trojan‑worker</h1>
  <input name="password" type="password" placeholder="رمز ۸ رقمی را وارد کنید" inputmode="numeric" pattern="\\d{8}" required autofocus />
  <button type="submit">ورود</button>
  <div class="hint">رمز پیش‌فرض: <strong>12345678</strong></div>
  <div class="small">۳ بار تلاش اشتباه => مسدودیت موقت</div>
</form>
</body>
</html>`;
}

// HTML پنل (بعد از لاگین) — ساده و تمیز
function htmlPanelPage(workerHostname) {
  // workerHostname را برای نمایش لینک استفاده می‌کنیم
  return `<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Trojan‑worker Panel</title>
<style>
  body{font-family:Arial,Helvetica,sans-serif;background:#f0f8ff;margin:0;padding:18px;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .container{width:760px;max-width:98%;background:#fff;padding:22px;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.06)}
  h1{margin:0 0 14px;font-size:22px}
  label{display:block;margin-top:8px;color:#333;font-weight:600}
  select,input[type=text]{width:100%;padding:10px;margin-top:6px;border:1px solid #e6e9ef;border-radius:8px;font-size:15px;box-sizing:border-box}
  .row{display:flex;gap:12px;margin-top:12px;flex-wrap:wrap}
  .col{flex:1;min-width:160px}
  button{padding:10px 14px;background:#0b84ff;color:#fff;border:0;border-radius:8px;cursor:pointer;font-size:15px}
  button.secondary{background:#6c757d}
  .result{margin-top:16px;background:#eef6ff;padding:12px;border-radius:8px;font-family:monospace;white-space:pre-wrap;max-height:360px;overflow:auto}
  .footer{margin-top:12px;color:#666;font-size:13px}
  a.link{color:#0b84ff;text-decoration:none}
  .controls{display:flex;gap:10px;flex-wrap:wrap}
  .top-links{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  code.suburl{background:#fff;padding:6px;border-radius:6px;border:1px dashed #dbe9ff}
</style>
</head>
<body>
<div class="container">
  <h1>Trojan‑worker Panel</h1>

  <div class="top-links">
    <div>GitHub repo: <a class="link" target="_blank" href="https://github.com/tepo18">https://github.com/tepo18</a></div>
    <div style="margin-left:auto">Worker base: <code class="suburl">https://${workerHostname}/sub/</code></div>
  </div>

  <label for="count">تعداد کانفیگ خروجی</label>
  <select id="count">
    <option value="50">50</option>
    <option value="500">500</option>
    <option value="1500" selected>1500</option>
    <option value="3000">3000</option>
    <option value="all">All</option>
  </select>

  <label for="ip">آی‌پی تمیز (اختیاری) — اگر خالی باشد از host استفاده می‌شود</label>
  <input id="ip" placeholder="مثلاً 104.18.101.226" />

  <div class="row">
    <div class="col controls">
      <button id="gen">ساخت لینک ساب (کپی به کلیپ‌بورد)</button>
    </div>
    <div class="col controls">
      <button id="preview" class="secondary">نمایش پیش‌نمایش کانفیگ‌ها</button>
      <button id="refresh" class="secondary">رفرش صفحه</button>
    </div>
  </div>

  <div style="margin-top:12px">
    <div><strong>لینک ساخته شده (کلیک یا کپی):</strong></div>
    <div id="link" class="result"></div>
  </div>

  <div style="margin-top:12px">
    <div><strong>پیش‌نمایش کانفیگ‌ها (تا 500 خط):</strong></div>
    <div id="previewBox" class="result">برای دیدن، روی «نمایش پیش‌نمایش کانفیگ‌ها» کلیک کنید.</div>
  </div>

  <div class="footer">Developed by Surfboardv2ray — merged panel (auth) by helper</div>
</div>

<script>
  const genBtn = document.getElementById('gen');
  const previewBtn = document.getElementById('preview');
  const refreshBtn = document.getElementById('refresh');
  const linkDiv = document.getElementById('link');
  const previewBox = document.getElementById('previewBox');

  function buildSubLink() {
    const count = document.getElementById('count').value;
    const ip = document.getElementById('ip').value.trim();
    let url = location.origin + '/sub';
    // use n param (compatible with original worker) or "all"
    if (count && count !== 'all') url += '?n=' + encodeURIComponent(count);
    if (ip) url += (url.includes('?') ? '&' : '?') + 'ip=' + encodeURIComponent(ip);
    return url;
  }

  genBtn.addEventListener('click', () => {
    const link = buildSubLink();
    linkDiv.textContent = link;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(link).catch(()=>{});
    }
  });

  previewBtn.addEventListener('click', async () => {
    previewBox.textContent = 'در حال واکشی و فیلتر کانفیگ‌ها …';
    try {
      const res = await fetch(buildSubLink());
      if (!res.ok) {
        previewBox.textContent = 'خطا: ' + res.status + ' ' + res.statusText;
        return;
      }
      const text = await res.text();
      if (!text) {
        previewBox.textContent = 'خطا: داده‌ای برای نمایش وجود ندارد.';
        return;
      }
      const lines = text.split('\\n').filter(Boolean);
      previewBox.textContent = lines.slice(0, 500).join('\\n');
    } catch (e) {
      previewBox.textContent = 'خطا در واکشی: ' + e.message;
    }
  });

  refreshBtn.addEventListener('click', () => location.reload());

  // نمایش لینک پیش‌فرض در بارگذاری
  linkDiv.textContent = buildSubLink();
</script>
</body>
</html>`;
}

// ---------- export handler (Cloudflare Worker) ----------
export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const path = url.pathname || "/";
      const method = request.method || "GET";

      // --- بررسی کوکی لاگین و بلاک --- 
      const cookieVal = getCookie(request, "sess_auth");
      const isAuth = cookieVal === "1";
      const blocked = getCookie(request, "blocked") === "1";
      const failCount = parseInt(getCookie(request, "failcount") || "0", 10);

      // صفحهٔ ورود (GET)
      if ((path === "/" || path === "/index.html") && method === "GET") {
        if (blocked) {
          return new Response(`<html><body><h3>دسترسی موقتاً مسدود است. بعد از مدتی دوباره تلاش کنید.</h3></body></html>`, { headers: { "Content-Type": "text/html; charset=UTF-8" } , status: 403 });
        }
        if (!isAuth) {
          return new Response(htmlLoginPage(), { headers: { "Content-Type": "text/html; charset=UTF-8" } });
        } else {
          return new Response(null, { status: 302, headers: { "Location": "/panel" } });
        }
      }

      // ارسال فرم لاگین (POST)
      if ((path === "/" || path === "/index.html") && method === "POST") {
        if (blocked) {
          return new Response(`<html><body><h3>دسترسی موقتاً مسدود است. بعد از مدتی دوباره تلاش کنید.</h3></body></html>`, { headers: { "Content-Type": "text/html; charset=UTF-8" }, status: 403 });
        }
        const bodyText = await request.text();
        const data = parseFormUrlencoded(bodyText);
        const pass = (data.password || "").trim();

        if (pass === PASSWORD) {
          // موفق => ست کوکی sess_auth و پاک کردن failcount
          return new Response(null, {
            status: 302,
            headers: {
              "Location": "/panel",
              "Set-Cookie": setCookieHeader("sess_auth", "1", 60 * 60),
              "Set-Cookie-2": setCookieHeader("failcount", "0", 60 * 60)
            }
          });
        } else {
          // ناموفق => افزایش failcount و در صورت رسیدن به 3 => بلاک موقت
          const newFail = failCount + 1;
          const headers = { "Content-Type": "text/html; charset=UTF-8", "Set-Cookie": setCookieHeader("failcount", String(newFail), 60 * 30) };
          if (newFail >= 3) {
            headers["Set-Cookie-2"] = setCookieHeader("blocked", "1", 60 * 5); // بلاک 5 دقیقه‌ای
            return new Response(`<html><body><h3>سه بار تلاش ناموفق. دسترسی برای ۵ دقیقه مسدود شد.</h3></body></html>`, { status: 403, headers });
          }
          return new Response(`<html><body><h3>رمز اشتباه است. (${newFail}/3)</h3><p><a href="/">بازگشت</a></p></body></html>`, { status: 401, headers });
        }
      }

      // صفحه پنل (GET /panel)
      if (path === "/panel") {
        if (!isAuth) return new Response(null, { status: 302, headers: { "Location": "/" } });
        return new Response(htmlPanelPage(url.hostname), { headers: { "Content-Type": "text/html; charset=UTF-8" } });
      }

      // endpoint /sub — خروجی کانفیگ‌ها
      if (path.startsWith("/sub")) {
        // قابل دریافت از query: n (تعداد) یا ip (clean ip)
        const params = url.searchParams;
        const nParamRaw = params.get("n") || params.get("count");
        const ipParam = (params.get("ip") || "").trim();

        // همچنین پشتیبانی از مسیر /sub/{clean-ip}
        let pathSegments = url.pathname.split("/").filter(Boolean);
        let pathCleanIp = pathSegments.length >= 2 ? pathSegments[1] : "";
        const cleanIp = ipParam || pathCleanIp || "";

        const selected = getCurrentSources();

        // واکشی همزمان منابع
        const fetchPromises = selected.map(s => fetch(s).then(r => r.ok ? r.text() : "").catch(() => ""));
        const results = await Promise.all(fetchPromises);
        const allText = results.join("\n");
        const lines = allText.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

        // filter & transform (keep original ip-rewrite logic intact)
        const validProtocols = ["ss://", "trojan://", "vmess://", "vless://"];
        const forbidden = ["error", "fail", "not found", "exception", "hello", "invalid", "code", "110"];
        const seen = new Set();
        const out = [];
        // We'll reuse a similar transform as original: but preserve the original replacement logic below
        // For simplicity here, we will call the full transformation loop (vmess/vless/trojan)
        let newConfigs = "";
        const trojanPaths = new Set();
        const vlessPaths = new Set();
        const vmessPaths = new Set();

        for (const raw of lines) {
          const subConfig = (raw || "").trim();
          if (!subConfig) continue;
          try {
            // vmess
            if (subConfig.startsWith("vmess://")) {
              try {
                const vmessData = subConfig.replace("vmess://", "");
                const decoded = atob(vmessData);
                const vmessConfig = JSON.parse(decoded);
                if (vmessConfig.sni && !isIp(vmessConfig.sni) && vmessConfig.net === "ws" && (vmessConfig.port === 443 || String(vmessConfig.port) === "443")) {
                  if (shouldSkipHost(vmessConfig.sni)) continue;
                  const path = `/${vmessConfig.sni}${vmessConfig.path || ""}`;
                  if (vmessPaths.has(path)) continue;
                  vmessPaths.add(path);
                  const newConf = {
                    v: "2",
                    ps: `Node-${vmessConfig.sni}`,
                    add: cleanIp || url.hostname,
                    port: vmessConfig.port,
                    id: vmessConfig.id,
                    net: vmessConfig.net,
                    type: "ws",
                    host: url.hostname,
                    path: path,
                    tls: vmessConfig.tls,
                    sni: url.hostname,
                    aid: "0",
                    scy: "auto",
                    fp: "chrome",
                    alpn: "http/1.1"
                  };
                  newConfigs += "vmess://" + btoa(JSON.stringify(newConf)) + "\n";
                }
              } catch (e) { /* ignore malformed vmess */ }
            } else if (subConfig.startsWith("vless://")) {
              try {
                const after = subConfig.replace("vless://", "");
                const parts = after.split("?");
                if (parts.length < 2) continue;
                const head = parts[0];
                const query = parts.slice(1).join("?");
                const [uuid, hostport] = head.split("@");
                if (!hostport) continue;
                const [host, port] = hostport.split(":");
                if (!port) continue;
                const q = new URLSearchParams(query);
                const security = q.get("security");
                const sni = q.get("sni");
                const type = q.get("type");
                const pathPart = decodeURIComponent(q.get("path") || "");
                if (sni && !isIp(sni) && security === "tls" && port === "443" && type === "ws") {
                  if (shouldSkipHost(sni)) continue;
                  const newPath = `/${sni}${pathPart}`;
                  if (vlessPaths.has(newPath)) continue;
                  vlessPaths.add(newPath);
                  const newVless = `vless://${uuid}@${cleanIp || url.hostname}:443?encryption=none&security=${security}&sni=${url.hostname}&alpn=http/1.1&fp=chrome&allowInsecure=1&type=ws&host=${url.hostname}&path=${encodeURIComponent(newPath)}#Node-${sni}`;
                  newConfigs += newVless + "\n";
                }
              } catch (e) { /* ignore malformed vless */ }
            } else if (subConfig.startsWith("trojan://")) {
              try {
                let configLine = subConfig;
                let remark = "";
                const idx = subConfig.lastIndexOf("#");
                if (idx !== -1) {
                  configLine = subConfig.substring(0, idx);
                  remark = subConfig.substring(idx + 1);
                }
                const after = configLine.replace("trojan://", "");
                const [beforeQuery, query] = after.split("?");
                if (!query) continue;
                const [passwordAndHost] = [beforeQuery];
                const [password, hostport] = passwordAndHost.split("@");
                if (!hostport) continue;
                const [host, port] = hostport.split(":");
                if (!port) continue;
                const q = new URLSearchParams(query);
                const security = q.get("security");
                const sni = q.get("sni");
                const type = q.get("type");
                const pathPart = decodeURIComponent(q.get("path") || "");
                if (sni && !isIp(sni) && security === "tls" && port === "443" && type === "ws") {
                  if (shouldSkipHost(sni)) continue;
                  const newPath = `/${sni}${pathPart}`;
                  if (trojanPaths.has(newPath)) continue;
                  trojanPaths.add(newPath);
                  const newTrojan = `trojan://${password}@${cleanIp || url.hostname}:443?security=${security}&sni=${url.hostname}&alpn=http/1.1&fp=chrome&allowInsecure=1&type=ws&host=${url.hostname}&path=${encodeURIComponent(newPath)}#Node-${sni}`;
                  newConfigs += newTrojan + "\n";
                }
              } catch (e) { /* ignore malformed trojan */ }
            }
          } catch (e) {
            // ignore and continue to next line
            continue;
          }
        } // end for lines

        // پارامتر n برای خروجی محدود
        const nParam = nParamRaw;
        const allLines = newConfigs.trim().split("\n").filter(Boolean);
        if (nParam && !isNaN(nParam) && parseInt(nParam, 10) > 0) {
          const n = Math.min(parseInt(nParam, 10), allLines.length);
          const randoms = getRandomItems(allLines, n);
          return new Response(randoms.join("\n"), { headers: { "Content-Type": "text/plain; charset=UTF-8" } });
        }
        // اگر مقدار 'all' ارسال شده یا nParam خالی => برگرداندن همه
        return new Response(allLines.join("\n"), { headers: { "Content-Type": "text/plain; charset=UTF-8" } });
      }

      // بقیه مسیرها: پروکسی ساده (مثل سازنده)
      {
        const splitted = url.pathname.replace(/^\/*/, "").split("/");
        const address = splitted[0] || "";
        if (!address) return new Response("Not found", { status: 404 });
        url.pathname = splitted.slice(1).join("/");
        url.hostname = address;
        url.protocol = "https:";
        return fetch(new Request(url.toString(), request));
      }
    } catch (err) {
      return new Response("Server error: " + String(err && err.message ? err.message : err), { status: 500 });
    }
  }
};
