// Developed by Surfboardv2ray, https://github.com/Surfboardv2ray/Trojan-worker
// Version 1.4.1
// Tips: Change your subLinks accordingly. Note that only ws+tls+443 configs will work.
// Your subscription link will be: 'https://{your_worker_address}.workers.dev/sub/{your_clean_ip}'
// To get xxx number of configs, use '?n=xxx' at the end of your subscription link, for instance:
// 'https://{your_worker_address}.workers.dev/sub/{your_clean_ip}?n=50' will return only 50 configs, randomly.

const PASSWORD = "1560";

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

  // منابع جدید اضافه شده (بدون تکراری)
  "https://raw.githubusercontent.com/tepo18/online-sshmax98/main/config3.txt",
  "https://raw.githubusercontent.com/tepo18/sab-vip15606/main/config.txt",
  "https://ahsan-tepo1383.almasi-ali98.workers.dev/config3.txt",
  "https://ahsan-tepo1383.almasi-ali98.workers.dev/config5.txt",
  "https://ahsan-tepo1383.almasi-ali98.workers.dev/config.txt",
  "https://sab-vip10.ahsan-tepo1383online.workers.dev/config.txt",
  "https://sab-vip10.ahsan-tepo1383online.workers.dev/config4.txt"
];

export default {
  async fetch(request) {
    let url = new URL(request.url);
    let pathSegments = url.pathname.split('/').filter(segment => segment !== '');
    let realhostname = pathSegments[0] || '';
    let realpathname = pathSegments[1] || '';

    if (url.pathname === '/') {
      return new Response(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <meta http-equiv="X-UA-Compatible" content="ie=edge" />
          <title>Trojan-worker</title>
          <style>
            body {
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              background-color: #f0f8ff;
              color: #333;
              margin: 0;
              padding: 0;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              flex-direction: column;
            }
            .container {
              text-align: center;
              padding: 20px;
              border-radius: 10px;
              background-color: #ffffff;
              box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
              width: 320px;
            }
            a {
              color: #007BFF;
              text-decoration: none;
            }
            a:hover {
              text-decoration: underline;
            }
            p {
              margin: 20px 0;
            }
            input[type="password"] {
              font-size: 20px;
              padding: 8px 12px;
              width: 100%;
              box-sizing: border-box;
              margin-bottom: 15px;
              border: 1.5px solid #007BFF;
              border-radius: 6px;
              text-align: center;
              letter-spacing: 4px;
              font-weight: bold;
            }
            button {
              padding: 10px 20px;
              border: none;
              border-radius: 5px;
              background-color: #007BFF;
              color: #ffffff;
              cursor: pointer;
              margin-top: 10px;
              width: 100%;
              font-size: 18px;
              font-weight: 600;
            }
            button:hover {
              background-color: #0056b3;
            }
            #error-msg {
              color: red;
              font-weight: 600;
              margin-top: 10px;
              min-height: 24px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Developed by Surfboardv2ray</h1>
            <p><a href="https://github.com/Surfboardv2ray/Trojan-worker" target="_blank">https://github.com/Surfboardv2ray/Trojan-worker</a></p>
            <input type="password" id="password-input" placeholder="Enter 4-digit password" maxlength="4" />
            <button id="get-clean-ip">Get Clean IP</button>
            <div id="error-msg"></div>
            <p id="subscription-link"><strong>https://{worker-address}/sub/{clean-ip}</strong></p>
          </div>
          <script>
            const PASSWORD = "${PASSWORD}";

            document.getElementById('get-clean-ip').onclick = async function() {
              const pwdInput = document.getElementById('password-input');
              const errorMsg = document.getElementById('error-msg');
              const password = pwdInput.value.trim();
              errorMsg.textContent = '';
              if (password !== PASSWORD) {
                errorMsg.textContent = 'Incorrect password!';
                document.getElementById('subscription-link').innerHTML = '<strong>https://{worker-address}/sub/{clean-ip}</strong>';
                return;
              }
              
              try {
                const response = await fetch('https://raw.githubusercontent.com/ircfspace/cf2dns/refs/heads/master/list/ipv4.json');
                const data = await response.json();
                const randomIndex = Math.floor(Math.random() * data.length);
                const cleanIP = data[randomIndex].ip;
                const workerAddress = window.location.hostname;
                const subscriptionLink = \`https://\${workerAddress}/sub/\${cleanIP}\`;
                document.getElementById('subscription-link').innerHTML = \`<a href="\${subscriptionLink}" target="_blank">\${subscriptionLink}</a>\`;
              } catch (e) {
                errorMsg.textContent = 'Failed to fetch IP data.';
              }
            };
          </script>
        </body>
        </html>
      `, {
        headers: { "Content-Type": "text/html" },
      });
    }

    let trojanPaths = new Set();
    let vlessPaths = new Set();
    let vmessPaths = new Set();

    if (url.pathname.startsWith('/sub')) {
      let newConfigs = '';

      for (let subLink of subLinks) {
        try {
          let resp = await fetch(subLink);
          if (!resp.ok) continue;
          let subConfigs = await resp.text();
          let isBase64Encoded = false;

          try { atob(subConfigs); isBase64Encoded = true; } catch (e) { isBase64Encoded = false; }
          if (isBase64Encoded) subConfigs = atob(subConfigs);

          subConfigs = subConfigs.split(/\r?\n/);

          for (let subConfig of subConfigs) {
            subConfig = subConfig.trim();
            if (subConfig === '') continue;

            try {
              if (subConfig.startsWith('vmess://')) {
                let vmessData = subConfig.replace('vmess://', '');
                vmessData = atob(vmessData);
                let vmessConfig = JSON.parse(vmessData);

                if (vmessConfig.sni && !isIp(vmessConfig.sni) && vmessConfig.net === 'ws' && vmessConfig.port === 443) {
                  if (shouldSkipHost(vmessConfig.sni)) continue;

                  let configNew = {
                    v: '2',
                    ps: `Node-${vmessConfig.sni}`,
                    add: realpathname === '' ? url.hostname : realpathname,
                    port: vmessConfig.port,
                    id: vmessConfig.id,
                    net: vmessConfig.net,
                    type: 'ws',
                    host: url.hostname,
                    path: `/${vmessConfig.sni}${vmessConfig.path}`,
                    tls: vmessConfig.tls,
                    sni: url.hostname,
                    aid: '0',
                    scy: 'auto',
                    fp: 'chrome',
                    alpn: 'http/1.1',
                  };

                  let fullPath = configNew.path;
                  if (!vmessPaths.has(fullPath)) {
                    vmessPaths.add(fullPath);
                    let encodedVmess = 'vmess://' + btoa(JSON.stringify(configNew));
                    newConfigs += encodedVmess + '\n';
                  }
                }
              } else if (subConfig.startsWith('vless://')) {
                let vlessParts = subConfig.replace('vless://', '').split('@');
                if (vlessParts.length !== 2) continue;

                let uuid = vlessParts[0];
                let remainingParts = vlessParts[1].split('?');
                if (remainingParts.length !== 2) continue;

                let [ipPort, params] = remainingParts;
                let [ip, port] = ipPort.split(':');
                if (!port) continue;

                let queryParams = new URLSearchParams(params);
                let security = queryParams.get('security');
                let sni = queryParams.get('sni');
                let type = queryParams.get('type');
                if (sni && !isIp(sni) && security === 'tls' && port === '443' && type === 'ws') {
                  if (shouldSkipHost(sni)) continue;

                  let newPath = `/${sni}${decodeURIComponent(queryParams.get('path') || '')}`;
                  if (!vlessPaths.has(newPath)) {
                    vlessPaths.add(newPath);
                    let newVlessConfig = `vless://${uuid}@${realpathname === '' ? url.hostname : realpathname}:${port}?encryption=none&security=${security}&sni=${url.hostname}&alpn=http/1.1&fp=chrome&allowInsecure=1&type=ws&host=${url.hostname}&path=${newPath}#Node-${sni}`;
                    newConfigs += newVlessConfig + '\n';
                  }
                }
              } else if (subConfig.startsWith('tro
