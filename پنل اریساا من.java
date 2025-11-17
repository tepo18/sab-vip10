addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const configCache = new Map();
const validDomains = ['raw.githubusercontent.com', 'trusted-source.com'];

let settings = {
  remoteDNS: [],
  directDNS: [],
  domains: [],
  cleanIPs: [],
  snis: [],
  useIPv6: false,
  selectedProtocols: [],
  selectedPorts: [],
  enableUDP: false,
  tlsMode: 'none',
  fragment: {
    enabled: false,
    size: 1200,
    interval: 100,
    packets: 3,
    clashMetaFormat: false
  }
};

const jsYaml = {
  load: (content) => {
    try {
      return JSON.parse(JSON.stringify(content));
    } catch (e) {
      return null;
    }
  },
  dump: (obj) => {
    return JSON.stringify(obj, null, 2).replace(/"/g, '').replace(/,\n/g, '\n');
  }
};

async function handleRequest(request) {
  const url = new URL(request.url);
  const uuid = request.headers.get('X-User-UUID') || '';
  const cache = caches.default;
  const subscribePaths = ['/subscribe', '/subscribe/clash.yaml', '/subscribe/v2ray.txt'];

  if (!subscribePaths.includes(url.pathname) && url.pathname !== '/' && url.pathname !== '/login') {
    if (url.pathname === '/panel' && request.method !== 'POST') {
    } else if (!uuid || uuid !== UUID) {
      return new Response('Invalid or missing UUID. Please provide your UUID in the X-User-UUID header.', {
        status: 403,
        headers: { 'content-type': 'text/plain' }
      });
    }
  }

  if (uuid) {
    try {
      const kvSettings = await ARISTA.get(`settings-${uuid}`, { type: 'json' });
      if (kvSettings) {
        settings = { 
          ...settings, 
          ...kvSettings,
          remoteDNS: kvSettings.remoteDNS || [],
          directDNS: kvSettings.directDNS || [],
          domains: kvSettings.domains || [],
          cleanIPs: kvSettings.cleanIPs || [],
          snis: kvSettings.snis || [],
          selectedProtocols: kvSettings.selectedProtocols || [],
          selectedPorts: kvSettings.selectedPorts || [],
          fragment: kvSettings.fragment || {
            enabled: false,
            size: 1200,
            interval: 100,
            packets: 3,
            clashMetaFormat: false
          }
        };
      }
    } catch (e) {
      console.error('Error loading settings:', e);
    }
  }

  if (url.pathname === '/') {
    return new Response('Hello User', {
      headers: { 'content-type': 'text/plain' }
    });
  }

  if (url.pathname === '/login') {
    if (request.method === 'POST') {
      const formData = await request.formData();
      const password = formData.get('password');
      if (password === ARISTA_PROJECT) {
        const sessionToken = `${UUID}-${Date.now()}`;
        await ARISTA.put(`session-${UUID}`, sessionToken, { expirationTtl: 86400 });
        return new Response(renderPanel(), {
          headers: {
            'content-type': 'text/html',
            'Set-Cookie': `session=${sessionToken}; Path=/; HttpOnly`
          }
        });
      } else {
        return new Response(renderLoginPage('Invalid password. Please try again.'), {
          headers: { 'content-type': 'text/html' },
          status: 401
        });
      }
    }
    return new Response(renderLoginPage(), {
      headers: { 'content-type': 'text/html' }
    });
  }

  if (url.pathname === '/panel') {
    if (request.method === 'GET') {
      const cookies = request.headers.get('Cookie') || '';
      const sessionMatch = cookies.match(/session=([^;]+)/);
      const sessionToken = sessionMatch ? sessionMatch[1] : null;
      const storedSession = await ARISTA.get(`session-${UUID}`);

      if (!sessionToken || sessionToken !== storedSession) {
        return new Response('Unauthorized. Please login first.', {
          status: 401,
          headers: { 'content-type': 'text/plain' }
        });
      }

      const cacheKey = `${url.origin}/panel`;
      let response = await cache.match(cacheKey);
      if (!response) {
        response = new Response(renderPanel(), {
          headers: {
            'content-type': 'text/html',
            'Cache-Control': 'public, max-age=86400'
          }
        });
        event.waitUntil(cache.put(cacheKey, response.clone()));
      }
      return response;
    }

    if (request.method === 'POST') {
      const body = await request.json();
      const validationErrors = validateSettings(body);

      if (validationErrors.length > 0) {
        return new Response(validationErrors.join('\n'), {
          headers: { 'content-type': 'text/plain' },
          status: 400
        });
      }

      const newSettings = {
        remoteDNS: Array.isArray(body.remoteDNS) ? body.remoteDNS : [],
        directDNS: Array.isArray(body.directDNS) ? body.directDNS : [],
        domains: Array.isArray(body.domains) ? body.domains : [],
        cleanIPs: Array.isArray(body.cleanIPs) ? body.cleanIPs : [],
        snis: Array.isArray(body.snis) ? body.snis : [],
        useIPv6: Boolean(body.useIPv6),
        selectedProtocols: Array.isArray(body.selectedProtocols) ? body.selectedProtocols : [],
        selectedPorts: Array.isArray(body.selectedPorts) ? body.selectedPorts : [],
        enableUDP: Boolean(body.enableUDP),
        tlsMode: ['none', 'tls', 'xtls'].includes(body.tlsMode) ? body.tlsMode : 'none',
        fragment: {
          enabled: Boolean(body.fragment?.enabled),
          clashMetaFormat: Boolean(body.fragment?.clashMetaFormat),
          size: Number(body.fragment?.size) || 1200,
          interval: Number(body.fragment?.interval) || 100,
          packets: Number(body.fragment?.packets) || 3
        }
      };

      try {
        await ARISTA.put(`settings-${uuid}`, JSON.stringify(newSettings), { expirationTtl: 86400 * 30 });
        settings = newSettings;
        return new Response('Settings saved successfully.', {
          headers: { 'content-type': 'text/plain' }
        });
      } catch (e) {
        return new Response('Failed to save settings. Please try again.', {
          headers: { 'content-type': 'text/plain' },
          status: 500
        });
      }
    }
  }

  if (url.pathname === '/subscribe') {
    const cacheKey = `${url.href}`;
    let response = await cache.match(cacheKey);
    if (response) return response;

    const protocol = url.searchParams.get('protocol') || settings.selectedProtocols.join(',');
    const ports = url.searchParams.get('ports') || settings.selectedPorts.join(',');
    const fragmentParam = url.searchParams.get('fragment');
    const fragmentEnabled = fragmentParam === 'on' || fragmentParam === 'clash';
    const fragmentSize = url.searchParams.get('size') || settings.fragment.size;
    const fragmentInterval = url.searchParams.get('interval') || settings.fragment.interval;
    const clashMetaFormat = fragmentParam === 'clash' || settings.fragment.clashMetaFormat;

    const subscribeUrls = [
        "https://raw.githubusercontent.com/tepo18/sab-vip10/main/final.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/custom/ipv6.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/custom/udp.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/converted.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/IR.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hy2",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/config_lite.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/tuic.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/vmess.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/vless.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/reality.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/refs/heads/main/hysteria.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/ss.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/trojan.txt",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/refs/heads/main/protocols/trojan",    
    
      ];

    try {
      const rawConfigs = await fetchConfigs(subscribeUrls, settings.remoteDNS, settings.directDNS);
      const currentSettings = {
        ...settings,
        fragment: {
          enabled: fragmentEnabled,
          clashMetaFormat: clashMetaFormat,
          size: fragmentSize,
          interval: fragmentInterval,
          packets: settings.fragment.packets
        }
      };
      
      const categorizedConfigs = clashMetaFormat ? 
        generateClashConfig(ports, protocol, currentSettings) :
        generateV2rayConfig(protocol, ports, currentSettings);

      response = new Response(categorizedConfigs, {
        headers: {
          'content-type': clashMetaFormat ? 'application/yaml' : 'text/plain',
          'Cache-Control': 'public, max-age=3600'
        }
      });
      event.waitUntil(cache.put(cacheKey, response.clone()));
      return response;
    } catch (error) {
      return new Response(`Error: ${error.message}`, {
        headers: { 'content-type': 'text/plain' },
        status: 500
      });
    }
  }

  if (url.pathname === '/subscribe/clash.yaml') {
    const ports = url.searchParams.get('ports') || settings.selectedPorts.join(',');
    const protocol = url.searchParams.get('protocol') || settings.selectedProtocols.join(',');
    const fragmentParam = url.searchParams.get('fragment');
    const fragmentEnabled = fragmentParam === 'on' || fragmentParam === 'clash';
    const fragmentSize = url.searchParams.get('size') || settings.fragment.size;
    const fragmentInterval = url.searchParams.get('interval') || settings.fragment.interval;
    const clashMetaFormat = true;

    const clashConfig = await generateClashConfig(ports, protocol, {
      ...settings,
      fragment: {
        enabled: fragmentEnabled,
        clashMetaFormat: clashMetaFormat,
        size: fragmentSize,
        interval: fragmentInterval,
        packets: settings.fragment.packets
      }
    });
    return new Response(clashConfig, {
      headers: { 'content-type': 'application/yaml' }
    });
  }

  if (url.pathname === '/subscribe/v2ray.txt') {
    const protocol = url.searchParams.get('protocol') || settings.selectedProtocols.join(',');
    const ports = url.searchParams.get('ports') || settings.selectedPorts.join(',');
    const fragmentEnabled = url.searchParams.get('fragment') === 'on';
    const fragmentSize = url.searchParams.get('size') || settings.fragment.size;
    const fragmentInterval = url.searchParams.get('interval') || settings.fragment.interval;
    const clashMetaFormat = false;

    const v2rayConfig = await generateV2rayConfig(protocol, ports, {
      ...settings,
      fragment: {
        enabled: fragmentEnabled,
        clashMetaFormat: clashMetaFormat,
        size: fragmentSize,
        interval: fragmentInterval,
        packets: settings.fragment.packets
      }
    });
    return new Response(v2rayConfig, {
      headers: { 'content-type': 'text/plain' }
    });
  }

  return new Response('Arista Project - Worker Message', {
    headers: { 'content-type': 'text/html' }
  });
}

function renderLoginPage(errorMessage = '') {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Arista Project - Login</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      height: 100vh;
      background: url('https://images.unsplash.com/photo-1506748686214-e9df14d4d9d0?ixlib=rb-4.0.3&auto=format&fit=crop&w=1350&q=80') no-repeat center center fixed;
      background-size: cover;
      font-family: 'Arial', sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
    }
    .login-container {
      text-align: center;
      padding: 40px;
      background: rgba(255, 255, 255, 0.5);
      border-radius: 15px;
      box-shadow: 0 0 20px rgba(0, 0, 0, 0.2);
      max-width: 600px;
      width: 100%;
    }
    h1 {
      font-size: 36px;
      color: #001F3F;
      text-shadow: 2px 2px 4px rgba(255, 255, 255, 0.8);
      margin-bottom: 20px;
    }
    .info-box {
      background: rgba(255, 255, 255, 0.5);
      padding: 20px;
      border-radius: 10px;
      margin-bottom: 30px;
    }
    .info-box p {
      color: #000;
      font-size: 16px;
      line-height: 1.5;
    }
    .info-box a {
      color: #00008B;
      text-decoration: none;
      font-weight: bold;
    }
    .info-box a:hover {
      text-decoration: underline;
    }
    .password-box {
      background: #fff;
      padding: 15px;
      border: 2px solid #FF4500;
      border-radius: 8px;
      display: inline-block;
    }
    .password-box input {
      padding: 10px;
      font-size: 16px;
      border: none;
      outline: none;
      width: 200px;
    }
    .password-box button {
      padding: 10px 20px;
      background: #4CAF50;
      color: white;
      border: none;
      border-radius: 5px;
      cursor: pointer;
      font-size: 16px;
    }
    .password-box button:hover {
      background: #45a049;
    }
    .error-message {
      background: #FFC1CC;
      color: #000;
      padding: 10px;
      border-radius: 5px;
      margin-top: 15px;
      display: ${errorMessage ? 'block' : 'none'};
      animation: fadeOut 3s forwards;
    }
    @keyframes fadeOut {
      0% { opacity: 1; }
      80% { opacity: 1; }
      100% { opacity: 0; display: none; }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>Welcome to the Arista User Panel</h1>
    <div class="info-box">
      <p>Dear user!<br>The project provides you with free services with servers collected from various sources. For more information and to provide your own suggestions for improving and advancing the project, join the Telegram channel <a href="https://t.me/aristaproject" target="_blank">https://t.me/aristaproject</a></p>
    </div>
    <form method="POST" action="/login">
      <div class="password-box">
        <input type="password" name="password" placeholder="Enter Password" required>
        <button type="submit">Login</button>
      </div>
      <div class="error-message">${errorMessage}</div>
    </form>
  </div>
</body>
</html>
  `;
}

function renderPanel() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Arista Panel</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {
      background-color: #87CEEB;
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 20px;
    }
    header {
      background-color: #001F3F;
      color: white;
      padding: 10px;
      text-align: center;
      font-size: 24px;
    }
    .container {
      margin: 20px;
      padding: 20px;
      background-color: white;
      border-radius: 8px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    }
    .settings-section {
      background-color: #001F3F;
      color: white;
      padding: 15px;
      border-radius: 8px;
      margin-top: 20px;
    }
    .input-field {
      margin: 10px 0;
    }
    .input-field label {
      display: block;
      margin-bottom: 5px;
    }
    .input-field input, .input-field textarea {
      width: 100%;
      padding: 10px;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    .save-button {
      background-color: #4CAF50;
      color: white;
      padding: 10px 15px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      margin-top: 10px;
    }
    .save-message {
      margin-top: 10px;
      padding: 10px;
      background-color: white;
      border: 1px solid #4CAF50;
      color: #4CAF50;
      display: none;
    }
    .error-message {
      color: red;
    }
    .ipv6-container {
      background-color: #1E90FF;
      padding: 15px;
      border-radius: 8px;
      margin-top: 20px;
      border: 2px solid #4169E1;
    }
    .ipv6-route {
      background-color: #4169E1;
      color: white;
      padding: 10px;
      border-radius: 8px;
      text-align: center;
      margin-bottom: 10px;
      width: 70%;
      margin-left: auto;
      margin-right: auto;
    }
    .ipv6-section {
      background-color: #1E90FF;
      color: white;
      padding: 15px;
      border-radius: 8px;
      text-align: center;
      cursor: pointer;
      transition: background-color 0.3s;
    }
    .ipv6-section.active {
      background-color: #32CD32;
    }
    .port-selection {
      display: flex;
      justify-content: space-between;
      margin-top: 20px;
    }
    .port-card {
      width: 120px;
      height: 60px;
      background-color: #1E90FF;
      color: white;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      cursor: pointer;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
      transition: background-color 0.3s;
    }
    .port-card.selected {
      background-color: #4CAF50;
    }
    .protocol-selection {
      display: flex;
      justify-content: space-between;
      margin-top: 20px;
    }
    .protocol-card {
      width: 200px;
      height: 100px;
      background-color: #1E90FF;
      color: white;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      cursor: pointer;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
      transition: transform 0.3s;
    }
    .protocol-card:hover {
      transform: scale(1.05);
    }
    .protocol-card.active {
      background-color: #4CAF50;
      border: 2px solid gold;
    }
    .fragment-card {
      width: 200px;
      height: 100px;
      background-color: #1E90FF;
      color: white;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      cursor: pointer;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
      transition: transform 0.3s;
      margin-top: 20px;
    }
    .fragment-card.active {
      background-color: #4CAF50;
      border: 2px solid gold;
    }
    .fragment-settings {
      display: none;
      margin-top: 20px;
      padding: 15px;
      background-color: #f5f5f5;
      border-radius: 8px;
    }
    .fragment-type {
      display: flex;
      margin-top: 10px;
    }
    .fragment-type label {
      margin-right: 15px;
      cursor: pointer;
    }
    .copy-message {
      background-color: pink;
      color: black;
      padding: 10px;
      border-radius: 8px;
      text-align: center;
      margin-top: 20px;
      display: none;
    }
    .udp-tls-section {
      margin-top: 20px;
    }
    .udp-tls-section label {
      margin-right: 10px;
    }
    /* Wizard Styles */
    .wizard-container {
      background-color: #1E3A8A;
      color: white;
      padding: 20px;
      border-radius: 10px;
      margin-top: 20px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .wizard-header {
      display: flex;
      align-items: center;
      margin-bottom: 20px;
    }
    .wizard-icon {
      font-size: 24px;
      margin-right: 10px;
    }
    .wizard-title {
      font-size: 20px;
      font-weight: bold;
      color: #3B82F6;
    }
    .wizard-progress {
      height: 8px;
      background-color: #3B82F6;
      border-radius: 4px;
      margin-bottom: 20px;
      overflow: hidden;
    }
    .wizard-progress-bar {
      height: 100%;
      background-color: #10B981;
      width: 0;
      transition: width 0.3s;
    }
    .wizard-step {
      display: none;
    }
    .wizard-step.active {
      display: block;
    }
    .wizard-option {
      background-color: #3B82F6;
      color: white;
      padding: 15px;
      border-radius: 8px;
      margin: 10px 0;
      cursor: pointer;
      transition: all 0.3s;
      text-align: center;
    }
    .wizard-option:hover {
      background-color: #2563EB;
      transform: translateY(-2px);
    }
    .wizard-option-icon {
      font-size: 20px;
      margin-bottom: 5px;
    }
    .wizard-buttons {
      display: flex;
      justify-content: space-between;
      margin-top: 20px;
    }
    .wizard-button {
      padding: 10px 20px;
      border-radius: 5px;
      cursor: pointer;
      border: none;
      font-weight: bold;
    }
    .wizard-button.next {
      background-color: #3B82F6;
      color: white;
    }
    .wizard-button.back {
      background-color: #6B7280;
      color: white;
    }
    .wizard-button.test {
      background-color: #10B981;
      color: white;
    }
    .wizard-footer {
      margin-top: 20px;
      text-align: center;
    }
    .wizard-footer a {
      color: #93C5FD;
      text-decoration: none;
    }
    .wizard-footer a:hover {
      text-decoration: underline;
    }
    .wizard-recommendation {
      background-color: rgba(59, 130, 246, 0.2);
      padding: 15px;
      border-radius: 8px;
      margin-top: 15px;
      border-left: 4px solid #3B82F6;
    }
  </style>
  <script>
    let currentStep = 1;
    let selectedGoal = '';
    let recommendedSettings = {};

    function startWizard() {
      document.getElementById('mainPanel').style.display = 'none';
      document.getElementById('wizardPanel').style.display = 'block';
      updateProgress();
    }

    function closeWizard() {
      document.getElementById('mainPanel').style.display = 'block';
      document.getElementById('wizardPanel').style.display = 'none';
      currentStep = 1;
      updateProgress();
    }

    function nextStep() {
      if (currentStep < 3) {
        currentStep++;
        updateProgress();
        updateStepVisibility();
      } else {
        applyRecommendedSettings();
        closeWizard();
      }
    }

    function prevStep() {
      if (currentStep > 1) {
        currentStep--;
        updateProgress();
        updateStepVisibility();
      }
    }

    function updateProgress() {
      const progress = (currentStep / 3) * 100;
      document.getElementById('wizardProgressBar').style.width = progress + '%';
    }

    function updateStepVisibility() {
      document.querySelectorAll('.wizard-step').forEach((step, index) => {
        step.classList.toggle('active', index + 1 === currentStep);
      });
    }

    function selectGoal(goal) {
      selectedGoal = goal;
      document.querySelectorAll('.wizard-option').forEach(option => {
        option.style.backgroundColor = option.textContent.includes(goal) ? '#10B981' : '#3B82F6';
      });
      
      // Set recommended settings based on goal
      switch(goal) {
        case 'ð Speed':
          recommendedSettings = {
            protocols: ['vless', 'trojan'],
            ports: ['443', '8443'],
            tlsMode: 'tls',
            enableUDP: false,
            useIPv6: false,
            fragment: false
          };
          break;
        case 'ð Security':
          recommendedSettings = {
            protocols: ['trojan'],
            ports: ['443'],
            tlsMode: 'tls',
            enableUDP: false,
            useIPv6: false,
            fragment: false
          };
          break;
        case 'ð Bypass':
          recommendedSettings = {
            protocols: ['vmess', 'vless'],
            ports: ['80', '443', '8080'],
            tlsMode: 'none',
            enableUDP: true,
            useIPv6: true,
            fragment: true
          };
          break;
      }
      
      // Update recommendation display
      const recText = {
        'ð Speed': 'For maximum speed, VLESS/Trojan with TLS on ports 443/8443 is recommended.',
        'ð Security': 'For maximum security, Trojan with TLS on port 443 is recommended.',
        'ð Bypass': 'For bypassing restrictions, VMESS/VLESS with multiple ports and IPv6 is recommended.'
      }[goal];
      
      document.getElementById('wizardRecommendation').innerHTML = recText;
      nextStep();
    }

    function testConnection() {
      alert('Testing connection with recommended settings...');
      // In a real implementation, this would test the connection
    }

    function applyRecommendedSettings() {
      if (!selectedGoal) return;
      
      // Apply the recommended settings to the UI
      recommendedSettings.protocols.forEach(protocol => {
        const cards = document.querySelectorAll('.protocol-card');
        cards.forEach(card => {
          if (card.textContent.toLowerCase().includes(protocol)) {
            card.classList.add('active');
          }
        });
      });
      
      recommendedSettings.ports.forEach(port => {
        const cards = document.querySelectorAll('.port-card');
        cards.forEach(card => {
          if (card.textContent.includes(port)) {
            card.classList.add('selected');
          }
        });
      });
      
      document.getElementById('tlsMode').value = recommendedSettings.tlsMode;
      document.getElementById('enableUDP').checked = recommendedSettings.enableUDP;
      document.getElementById('ipv6Section').classList.toggle('active', recommendedSettings.useIPv6);
      
      if (recommendedSettings.fragment) {
        document.getElementById('fragmentCard').classList.add('active');
        document.getElementById('fragmentSettings').style.display = 'block';
      }
      
      alert('Recommended settings have been applied! You can further customize them or save.');
    }

    async function saveSettings() {
      const remoteDNS = document.getElementById('remoteDNS').value.split(',').map(v => v.trim()).filter(Boolean);
      const directDNS = document.getElementById('directDNS').value.split(',').map(v => v.trim()).filter(Boolean);
      const domains = document.getElementById('domains').value.split(',').map(v => v.trim()).filter(Boolean);
      const cleanIPs = document.getElementById('cleanIPs').value.split(',').map(v => v.trim()).filter(Boolean);
      const snis = document.getElementById('snis').value.split(',').map(v => v.trim()).filter(Boolean);
      const useIPv6 = document.getElementById('ipv6Section').classList.contains('active');
      const selectedProtocols = Array.from(document.querySelectorAll('.protocol-card.active')).map(card => card.innerText.toLowerCase());
      const selectedPorts = Array.from(document.querySelectorAll('.port-card.selected')).map(card => card.innerText);
      const enableUDP = document.getElementById('enableUDP').checked;
      const tlsMode = document.getElementById('tlsMode').value;
      const fragmentEnabled = document.getElementById('fragmentCard').classList.contains('active');
      const clashMetaFormat = document.getElementById('clashMetaFormat').checked;
      const fragmentSize = document.getElementById('fragmentSize').value;
      const fragmentInterval = document.getElementById('fragmentInterval').value;

      const response = await fetch('/panel', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-UUID': '${UUID}'
        },
        body: JSON.stringify({ 
          remoteDNS, 
          directDNS, 
          domains, 
          cleanIPs, 
          snis, 
          useIPv6, 
          selectedProtocols, 
          selectedPorts, 
          enableUDP, 
          tlsMode,
          fragment: {
            enabled: fragmentEnabled,
            clashMetaFormat: clashMetaFormat,
            size: fragmentSize,
            interval: fragmentInterval
          }
        })
      });

      if (response.ok) {
        document.getElementById('saveMessage').innerText = 'Settings saved successfully.';
        document.getElementById('saveMessage').style.display = 'block';
        setTimeout(() => document.getElementById('saveMessage').style.display = 'none', 3000);
      } else {
        const errorText = await response.text();
        document.getElementById('saveMessage').innerText = errorText;
        document.getElementById('saveMessage').style.display = 'block';
      }
    }

    function toggleIPv6() {
      const ipv6Section = document.getElementById('ipv6Section');
      ipv6Section.classList.toggle('active');
    }

    function selectPort(port) {
      const portCards = document.querySelectorAll('.port-card');
      if (port === 'All Ports') {
        portCards.forEach(card => {
          if (card.innerText === 'All Ports') {
            card.classList.toggle('selected');
          } else {
            card.classList.remove('selected');
          }
        });
      } else {
        portCards.forEach(card => {
          if (card.innerText === 'All Ports') {
            card.classList.remove('selected');
          }
          if (card.innerText === port) {
            card.classList.toggle('selected');
          }
        });
      }
    }

    function selectProtocol(protocol) {
      const protocolCards = document.querySelectorAll('.protocol-card');
      protocolCards.forEach(card => {
        if (card.innerText.toLowerCase() === protocol.toLowerCase()) {
          card.classList.toggle('active');
        }
      });
    }

    function toggleFragment() {
      const fragmentCard = document.getElementById('fragmentCard');
      fragmentCard.classList.toggle('active');
      document.getElementById('fragmentSettings').style.display = 
        fragmentCard.classList.contains('active') ? 'block' : 'none';
    }

    function generateLink() {
      const selectedPorts = Array.from(document.querySelectorAll('.port-card.selected')).map(card => card.innerText);
      const selectedProtocols = Array.from(document.querySelectorAll('.protocol-card.active')).map(card => card.innerText.toLowerCase());
      const fragmentEnabled = document.getElementById('fragmentCard').classList.contains('active');
      const clashMetaFormat = document.getElementById('clashMetaFormat').checked;
      const fragmentSize = document.getElementById('fragmentSize').value;
      const fragmentInterval = document.getElementById('fragmentInterval').value;

      if (selectedPorts.length === 0 || selectedProtocols.length === 0) {
        document.getElementById('copyMessage').innerText = 'Please select at least one port and one protocol.';
        document.getElementById('copyMessage').style.display = 'block';
        setTimeout(() => document.getElementById('copyMessage').style.display = 'none', 3000);
        return;
      }

      const baseUrl = window.location.origin;
      let link;

      if (clashMetaFormat) {
        link = baseUrl + '/subscribe/clash.yaml?protocol=' + selectedProtocols.join(',') + '&ports=' + selectedPorts.join(',');
        if (fragmentEnabled) {
          link += '&fragment=on&size=' + fragmentSize + '&interval=' + fragmentInterval;
        }
      } else {
        link = baseUrl + '/subscribe/v2ray.txt?protocol=' + selectedProtocols.join(',') + '&ports=' + selectedPorts.join(',');
        if (fragmentEnabled) {
          link += '&fragment=on&size=' + fragmentSize + '&interval=' + fragmentInterval;
        }
      }

      navigator.clipboard.writeText(link).then(() => {
        document.getElementById('copyMessage').innerText = 'Link copied!';
        document.getElementById('copyMessage').style.display = 'block';
        setTimeout(() => document.getElementById('copyMessage').style.display = 'none', 3000);
      });
    }

    window.onload = async () => {
      try {
        const response = await fetch('/panel', { 
          method: 'GET', 
          headers: { 
            'X-User-UUID': '${UUID}',
            'Accept': 'application/json'
          } 
        });
        if (response.ok) {
          const settings = await response.json();
          document.getElementById('remoteDNS').value = settings.remoteDNS?.join(',') || '';
          document.getElementById('directDNS').value = settings.directDNS?.join(',') || '';
          document.getElementById('domains').value = settings.domains?.join(',') || '';
          document.getElementById('cleanIPs').value = settings.cleanIPs?.join(',') || '';
          document.getElementById('snis').value = settings.snis?.join(',') || '';
          document.getElementById('enableUDP').checked = settings.enableUDP || false;
          document.getElementById('tlsMode').value = settings.tlsMode || 'none';
          if (settings.useIPv6) {
            document.getElementById('ipv6Section').classList.add('active');
          }
          (settings.selectedPorts || []).forEach(port => {
            const portCards = document.querySelectorAll('.port-card');
            portCards.forEach(card => {
              if (card.innerText === port.toString()) {
                card.classList.add('selected');
              }
            });
          });
          (settings.selectedProtocols || []).forEach(protocol => {
            const protocolCards = document.querySelectorAll('.protocol-card');
            protocolCards.forEach(card => {
              if (card.innerText.toLowerCase() === protocol.toLowerCase()) {
                card.classList.add('active');
              }
            });
          });
          if (settings.fragment?.enabled) {
            document.getElementById('fragmentCard').classList.add('active');
            document.getElementById('fragmentSettings').style.display = 'block';
            document.getElementById('fragmentSize').value = settings.fragment.size || 1200;
            document.getElementById('fragmentInterval').value = settings.fragment.interval || 100;
            document.getElementById('clashMetaFormat').checked = settings.fragment.clashMetaFormat || false;
          }
        }
      } catch (e) {
        console.error('Error loading settings:', e);
      }
    };
  </script>
</head>
<body>
  <header>Arista Panel</header>
  <div class="container" id="mainPanel">
    <h2>Welcome to the Arista Panel</h2>
    <p>You can manage your settings here or use the wizard for automatic configuration.</p>
    
    <button class="save-button" onclick="startWizard()" style="background-color: #3B82F6;">ð§ââï¸1¤7 Start Configuration Wizard</button>

    <div class="settings-section">
      <h3>Settings</h3>
      <div class="input-field">
        <label for="remoteDNS">Remote DNS (IP/Domain or IP/Domain,protocol):</label>
        <textarea id="remoteDNS" placeholder="e.g., 8.8.8.8 (defaults to UDP) or dns.google,https">${settings.remoteDNS.join(',')}</textarea>
        <div class="error-message" id="remoteDNSError"></div>
      </div>
      <div class="input-field">
        <label for="directDNS">Direct DNS (IP/Domain or IP/Domain,protocol):</label>
        <textarea id="directDNS" placeholder="e.g., 1.1.1.1 (defaults to UDP) or dns.google,tls">${settings.directDNS.join(',')}</textarea>
        <div class="error-message" id="directDNSError"></div>
      </div>
      <div class="input-field">
        <label for="domains">Domains (domain or full URL):</label>
        <textarea id="domains" placeholder="e.g., example.com or https://example.com">${settings.domains.join(',')}</textarea>
        <div class="error-message" id="domainsError"></div>
      </div>
      <div class="input-field">
        <label for="cleanIPs">Clean IPs (comma-separated):</label>
        <textarea id="cleanIPs" placeholder="e.g., 192.168.1.1,192.168.1.2">${settings.cleanIPs.join(',')}</textarea>
        <div class="error-message" id="cleanIPsError"></div>
      </div>
      <div class="input-field">
        <label for="snis">SNIs (comma-separated):</label>
        <textarea id="snis" placeholder="e.g., sni1.example.com,sni2.example.com">${settings.snis.join(',')}</textarea>
        <div class="error-message" id="snisError"></div>
      </div>
      <div class="udp-tls-section">
        <label><input type="checkbox" id="enableUDP" ${settings.enableUDP ? 'checked' : ''}> Enable UDP</label>
        <label>TLS Mode:
          <select id="tlsMode">
            <option value="none" ${settings.tlsMode === 'none' ? 'selected' : ''}>None</option>
            <option value="tls" ${settings.tlsMode === 'tls' ? 'selected' : ''}>TLS</option>
            <option value="xtls" ${settings.tlsMode === 'xtls' ? 'selected' : ''}>XTLS</option>
          </select>
        </label>
      </div>
      <button class="save-button" onclick="saveSettings()">Save Settings</button>
      <div id="saveMessage" class="save-message"></div>
    </div>

    <div class="ipv6-container">
      <div class="ipv6-route">
        <h3>IPv6 Route</h3>
      </div>
      <div id="ipv6Section" class="ipv6-section" onclick="toggleIPv6()">
        <h3>IPv6</h3>
      </div>
    </div>

    <div class="port-selection">
      <div class="port-card" onclick="selectPort('80')">80</div>
      <div class="port-card" onclick="selectPort('443')">443</div>
      <div class="port-card" onclick="selectPort('8080')">8080</div>
      <div class="port-card" onclick="selectPort('8443')">8443</div>
      <div class="port-card" onclick="selectPort('All Ports')">All Ports</div>
    </div>

    <div class="protocol-selection">
      <div class="protocol-card" onclick="selectProtocol('vmess')">VMess</div>
      <div class="protocol-card" onclick="selectProtocol('vless')">VLESS</div>
      <div class="protocol-card" onclick="selectProtocol('shadowsocks')">Shadowsocks</div>
      <div class="protocol-card" onclick="selectProtocol('trojan')">Trojan</div>
      <div class="protocol-card" onclick="selectProtocol('yaml')">YAML</div>
    </div>

    <div class="fragment-card" id="fragmentCard" onclick="toggleFragment()">
      Fragment
    </div>

    <div class="fragment-settings" id="fragmentSettings">
      <div class="fragment-type">
        <label>
          <input type="radio" name="fragmentType" id="v2rayFormat" ${!settings.fragment.clashMetaFormat ? 'checked' : ''}> 
          V2Ray/Hiddify Format
        </label>
        <label>
          <input type="radio" name="fragmentType" id="clashMetaFormat" ${settings.fragment.clashMetaFormat ? 'checked' : ''}> 
          Clash Meta Format
        </label>
      </div>
      <div class="input-field">
        <label for="fragmentSize">Fragment Size (bytes):</label>
        <input type="number" id="fragmentSize" value="${settings.fragment.size}" min="500" max="2000">
      </div>
      <div class="input-field">
        <label for="fragmentInterval">Fragment Interval (ms):</label>
        <input type="number" id="fragmentInterval" value="${settings.fragment.interval}" min="50" max="300">
      </div>
    </div>

    <button class="save-button" onclick="generateLink()">Copy Link</button>
    <div id="copyMessage" class="copy-message"></div>
  </div>

  <!-- Wizard Panel -->
  <div class="container" id="wizardPanel" style="display: none;">
    <div class="wizard-container">
      <div class="wizard-header">
        <div class="wizard-icon">â1¤7</div>
        <div class="wizard-title">Configuration Wizard</div>
      </div>
      <div class="wizard-progress">
        <div class="wizard-progress-bar" id="wizardProgressBar"></div>
      </div>
      
      <!-- Step 1: Goal Selection -->
      <div class="wizard-step active" id="step1">
        <h3>What is your main goal?</h3>
        <div class="wizard-option" onclick="selectGoal('ð Speed')">
          <div class="wizard-option-icon">ð</div>
          <div>Maximum Speed</div>
        </div>
        <div class="wizard-option" onclick="selectGoal('ð Security')">
          <div class="wizard-option-icon">ð</div>
          <div>Maximum Security</div>
        </div>
        <div class="wizard-option" onclick="selectGoal('ð Bypass')">
          <div class="wizard-option-icon">ð</div>
          <div>Bypass Restrictions</div>
        </div>
      </div>
      
      <!-- Step 2: Recommendation -->
      <div class="wizard-step" id="step2">
        <h3>Recommended Configuration</h3>
        <div class="wizard-recommendation" id="wizardRecommendation">
          Select a goal to see recommendations
        </div>
        <div class="wizard-buttons">
          <button class="wizard-button back" onclick="prevStep()">Back</button>
          <button class="wizard-button next" onclick="nextStep()">Next</button>
        </div>
      </div>
      
      <!-- Step 3: Apply Settings -->
      <div class="wizard-step" id="step3">
        <h3>Ready to Apply</h3>
        <p>Review the recommended settings and choose an action:</p>
        <div class="wizard-buttons">
          <button class="wizard-button back" onclick="prevStep()">Back</button>
          <button class="wizard-button test" onclick="testConnection()">Test Connection</button>
          <button class="wizard-button next" onclick="nextStep()">Apply Settings</button>
        </div>
      </div>
      
      <div class="wizard-footer">
        <a href="#" onclick="closeWizard()">Skip wizard and configure manually</a>
      </div>
    </div>
  </div>
</body>
</html>
  `;
}

function validateSettings(body) {
  const errors = [];
  const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Pattern = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^(?:[0-9a-fA-F]{1,4}:){1,1}(?::[0-9a-fA-F]{1,4}){1,6}$|^::(?:[0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}$/;
  const cleanIPPattern = new RegExp(`^(${ipv4Pattern.source}|${ipv6Pattern.source})$`);
  const sniPattern = /^[A-Za-z0-9.-]+$/;

  if (body.remoteDNS && Array.isArray(body.remoteDNS)) {
    body.remoteDNS.forEach(dns => {
      if (!validateDNS(dns)) {
        errors.push(`Invalid Remote DNS entry: ${dns}. Valid formats: IP or Domain (defaults to UDP), or IP/Domain,protocol (e.g., 8.8.8.8 or dns.google,https)`);
      }
    });
  }

  if (body.directDNS && Array.isArray(body.directDNS)) {
    body.directDNS.forEach(dns => {
      if (!validateDNS(dns)) {
        errors.push(`Invalid Direct DNS entry: ${dns}. Valid formats: IP or Domain (defaults to UDP), or IP/Domain,protocol (e.g., 1.1.1.1 or dns.google,tls)`);
      }
    });
  }

  if (body.domains && Array.isArray(body.domains)) {
    body.domains.forEach(domain => {
      if (!isValidDomain(domain)) {
        errors.push(`Invalid Domain entry: ${domain}. Must be a valid domain (e.g., example.com) or URL (e.g., https://example.com)`);
      }
    });
  }

  if (body.cleanIPs && Array.isArray(body.cleanIPs)) {
    body.cleanIPs.forEach(cleanIP => {
      if (!cleanIPPattern.test(cleanIP)) {
        errors.push(`Invalid Clean IP entry: ${cleanIP}. Must be a valid IPv4 or IPv6 address.`);
      }
    });
  }

  if (body.snis && Array.isArray(body.snis)) {
    body.snis.forEach(sni => {
      if (sni.length > 255 || !sniPattern.test(sni)) {
        errors.push(`Invalid SNI entry: ${sni}. Must contain only letters, numbers, dots, and hyphens, and cannot be longer than 255 characters.`);
      }
    });
  }

  if (body.tlsMode && !['none', 'tls', 'xtls'].includes(body.tlsMode)) {
    errors.push(`Invalid TLS mode: ${body.tlsMode}. Must be 'none', 'tls', or 'xtls'.`);
  }

  if (body.fragment) {
    if (body.fragment.size && (body.fragment.size < 500 || body.fragment.size > 2000)) {
      errors.push('Fragment size must be between 500 and 2000 bytes.');
    }
    if (body.fragment.interval && (body.fragment.interval < 50 || body.fragment.interval > 300)) {
      errors.push('Fragment interval must be between 50 and 300 milliseconds.');
    }
    if (typeof body.fragment.clashMetaFormat !== 'boolean') {
      errors.push('Invalid Clash Meta format flag.');
    }
  }

  return errors;
}

function validateDNS(dns) {
  if (!dns.includes(',')) {
    dns = `${dns},udp`;
  }
  const [value, protocol] = dns.split(',').map(v => v.trim());
  const validProtocols = ['udp', 'tls', 'https', 'http', 'quic'];
  const isValidValue = isValidIPv4(value) || isValidIPv6(value) || isValidDomain(value);
  return isValidValue && protocol && validProtocols.includes(protocol.toLowerCase());
}

function isValidDomain(url) {
  try {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      url = new URL(url).hostname;
    }
    const domainPattern = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$/;
    return domainPattern.test(url) || validDomains.includes(url);
  } catch (e) {
    return false;
  }
}

function isValidIPv4(address) {
  const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Pattern.test(address);
}

function isValidIPv6(address) {
  const ipv6Pattern = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^(?:[0-9a-fA-F]{1,4}:){1,1}(?::[0-9a-fA-F]{1,4}){1,6}$|^::(?:[0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}$/;
  return ipv6Pattern.test(address);
}

async function fetchConfigs(urls, remoteDNS, directDNS) {
  const allConfigs = {
    vmess: [],
    vless: [],
    shadowsocks: [],
    trojan: [],
    yaml: []
  };

  await Promise.all(urls.map(async (url) => {
    try {
      if (!isValidDomain(url)) {
        return;
      }

      if (configCache.has(url)) {
        processConfig(url, configCache.get(url), allConfigs, remoteDNS, directDNS);
        return;
      }

      const response = await fetch(url, { rejectUnauthorized: true });
      if (!response.ok) {
        return;
      }

      const text = await response.text();
      configCache.set(url, text);
      processConfig(url, text, allConfigs, remoteDNS, directDNS);
    } catch (error) {
    }
  }));

  return allConfigs;
}

function processConfig(url, text, allConfigs, remoteDNS, directDNS) {
  if (url.endsWith('.yaml') || url.endsWith('.yml')) {
    allConfigs.yaml.push(text.trim());
  } else if (url.endsWith('.txt')) {
    const lines = text.split('\n').map(line => line.trim()).filter(Boolean);
    const usedAddresses = new Set();

    lines.forEach(line => {
      let port, address;

      if (line.startsWith('vmess://')) {
        const match = line.match(/port["']?\s*[:=]\s*["']?(\d+)/);
        if (match) {
          port = match[1];
          address = line.match(/add["']?\s*[:=]\s*["']?([^"']+)/)?.[1];
          const serverKey = `${address}:${port}`;
          if (!usedAddresses.has(serverKey)) {
            usedAddresses.add(serverKey);
            allConfigs.vmess.push(processVmess(line, settings));
          }
        }
      } else if (line.startsWith('vless://')) {
        const match = line.match(/@([^:]+):(\d+)/);
        if (match) {
          address = match[1];
          port = match[2];
          const serverKey = `${address}:${port}`;
          if (!usedAddresses.has(serverKey)) {
            usedAddresses.add(serverKey);
            allConfigs.vless.push(processVless(line, settings));
          }
        }
      } else if (line.startsWith('ss://')) {
        const match = line.match(/@([^:]+):(\d+)/);
        if (match) {
          address = match[1];
          port = match[2];
          const serverKey = `${address}:${port}`;
          if (!usedAddresses.has(serverKey)) {
            usedAddresses.add(serverKey);
            allConfigs.shadowsocks.push(processShadowsocks(line, settings));
          }
        }
      } else if (line.startsWith('trojan://')) {
        const match = line.match(/@([^:]+):(\d+)/);
        if (match) {
          address = match[1];
          port = match[2];
          const serverKey = `${address}:${port}`;
          if (!usedAddresses.has(serverKey)) {
            usedAddresses.add(serverKey);
            allConfigs.trojan.push(processTrojan(line, settings));
          }
        }
      }
    });
  }
}

function processVmess(link, settings) {
  try {
    const base64 = link.replace('vmess://', '');
    const decoded = JSON.parse(atob(base64));
    if (settings.cleanIPs.length > 0) decoded.add = settings.cleanIPs.shift();
    if (settings.snis.length > 0) decoded.host = settings.snis.shift();
    if (settings.enableUDP) decoded.net = decoded.net === 'tcp' ? 'tcp' : 'udp';
    if (settings.tlsMode === 'tls') decoded.tls = 'tls';
    else if (settings.tlsMode === 'xtls') {
      decoded.tls = 'xtls';
      decoded.flow = 'xtls-rprx-direct';
    }
    if (settings.fragment.enabled) {
      if (settings.fragment.clashMetaFormat) {
        decoded.fragment = {
          enabled: true,
          size: settings.fragment.size,
          interval: settings.fragment.interval
        };
      } else {
        decoded.fragment = `${settings.fragment.size},${settings.fragment.interval}`;
      }
    }
    return `vmess://${btoa(JSON.stringify(decoded))}`;
  } catch (e) {
    return link;
  }
}

function processVless(link, settings) {
  try {
    const url = new URL(link);
    if (settings.cleanIPs.length > 0) url.hostname = settings.cleanIPs.shift();
    if (settings.snis.length > 0) url.searchParams.set('sni', settings.snis.shift());
    if (settings.enableUDP) url.searchParams.set('type', 'udp');
    if (settings.tlsMode === 'tls') url.searchParams.set('security', 'tls');
    else if (settings.tlsMode === 'xtls') {
      url.searchParams.set('security', 'xtls');
      url.searchParams.set('flow', 'xtls-rprx-direct');
    }
    if (settings.fragment.enabled) {
      if (settings.fragment.clashMetaFormat) {
        url.searchParams.set('fragment', 'clash');
      } else {
        url.searchParams.set('fragment', 'on');
      }
      url.searchParams.set('fragmentSize', settings.fragment.size.toString());
      url.searchParams.set('fragmentInterval', settings.fragment.interval.toString());
    }
    return url.toString();
  } catch (e) {
    return link;
  }
}

function processShadowsocks(link, settings) {
  try {
    const url = new URL(link);
    if (settings.cleanIPs.length > 0) url.hostname = settings.cleanIPs.shift();
    if (settings.enableUDP) url.searchParams.set('udp', 'true');
    if (settings.fragment.enabled) {
      if (settings.fragment.clashMetaFormat) {
        url.searchParams.set('fragment', 'clash');
      } else {
        url.searchParams.set('fragment', 'on');
      }
      url.searchParams.set('fragmentSize', settings.fragment.size.toString());
      url.searchParams.set('fragmentInterval', settings.fragment.interval.toString());
    }
    return url.toString();
  } catch (e) {
    return link;
  }
}

function processTrojan(link, settings) {
  try {
    const url = new URL(link);
    if (settings.cleanIPs.length > 0) url.hostname = settings.cleanIPs.shift();
    if (settings.snis.length > 0) url.searchParams.set('sni', settings.snis.shift());
    if (settings.enableUDP) url.searchParams.set('type', 'udp');
    if (settings.tlsMode === 'tls') url.searchParams.set('security', 'tls');
    if (settings.fragment.enabled) {
      if (settings.fragment.clashMetaFormat) {
        url.searchParams.set('fragment', 'clash');
      } else {
        url.searchParams.set('fragment', 'on');
      }
      url.searchParams.set('fragmentSize', settings.fragment.size.toString());
      url.searchParams.set('fragmentInterval', settings.fragment.interval.toString());
    }
    return url.toString();
  } catch (e) {
    return link;
  }
}

function categorizeConfigs(rawConfigs, protocol, ports, settings, fragmentEnabled, fragmentSize, fragmentInterval) {
  const isClashMeta = settings.fragment?.clashMetaFormat || false;
  let response = '';

  response += `${settings.useIPv6 ? 'IPv6 enabled' : 'IPv6 disabled'}, UDP: ${settings.enableUDP ? 'enabled' : 'disabled'}, TLS: ${settings.tlsMode}, Fragment: ${fragmentEnabled ? 'enabled' : 'disabled'}`;
  if (fragmentEnabled) {
    response += ` (${isClashMeta ? 'Clash Meta' : 'V2Ray'} format, size: ${fragmentSize}, interval: ${fragmentInterval})`;
  }
  response += '\n\n';

  if (isClashMeta) {
    const clashConfigs = rawConfigs.yaml.map(config => {
      const parsed = validateAndParseYaml(config);
      if (!parsed) return null;
      
      if (fragmentEnabled) {
        parsed.proxies.forEach(proxy => {
          proxy.fragment = {
            enabled: true,
            size: fragmentSize,
            interval: fragmentInterval
          };
        });
      }
      
      return jsYaml.dump(parsed);
    }).filter(Boolean);
    
    response += clashConfigs.join('\n---\n');
  } else {
    const protocolList = protocol ? protocol.split(',').map(p => p.toLowerCase()) : settings.selectedProtocols;
    const portList = ports ? ports.split(',') : settings.selectedPorts;

    const filterByPort = (configs) => {
      if (portList.length > 0 && !portList.includes('All Ports')) {
        return configs.filter(line => {
          const match = line.match(/@[^:]+:(\d+)/) || line.match(/port["']?\s*[:=]\s*["']?(\d+)/);
          return match && portList.includes(match[1]);
        });
      }
      return configs;
    };

    if (protocolList.length === 0) {
      response += 'No protocol specified.\n';
    } else {
      if (protocolList.includes('vmess')) {
        const vmessConfigs = filterByPort(rawConfigs.vmess);
        response += vmessConfigs.length > 0 ? vmessConfigs.join('\n') + '\n\n' : 'VMESS Configs: None\n\n';
      }
      if (protocolList.includes('vless')) {
        const vlessConfigs = filterByPort(rawConfigs.vless);
        response += vlessConfigs.length > 0 ? vlessConfigs.join('\n') + '\n\n' : 'VLESS Configs: None\n\n';
      }
      if (protocolList.includes('shadowsocks')) {
        const shadowsocksConfigs = filterByPort(rawConfigs.shadowsocks);
        response += shadowsocksConfigs.length > 0 ? shadowsocksConfigs.join('\n') + '\n\n' : 'Shadowsocks Configs: None\n\n';
      }
      if (protocolList.includes('trojan')) {
        const trojanConfigs = filterByPort(rawConfigs.trojan);
        response += trojanConfigs.length > 0 ? trojanConfigs.join('\n') + '\n\n' : 'Trojan Configs: None\n\n';
      }
    }
  }

  return response.trim();
}

function validateAndParseYaml(content) {
  try {
    if (!content || typeof content !== 'string') {
      throw new Error('Content is empty or not a string');
    }
    const parsed = jsYaml.load(content);
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid YAML structure');
    }
    return parsed;
  } catch (e) {
    return null;
  }
}

function filterYamlByPorts(yamlConfigs, portList) {
  return yamlConfigs.map(config => {
    const parsed = validateAndParseYaml(config);
    if (!parsed || !parsed.proxies) return config;
    parsed.proxies = parsed.proxies.filter(proxy =>
      portList.includes('All Ports') || (proxy.port && portList.includes(proxy.port.toString()))
    );
    return jsYaml.dump(parsed);
  }).filter(Boolean).join('\n---\n');
}

function applyUserSettingsToYaml(yamlConfigs, settings) {
  return yamlConfigs.map(config => {
    const parsed = validateAndParseYaml(config);
    if (!parsed) return config;

    if (settings.cleanIPs.length > 0 && parsed.proxies) {
      parsed.proxies.forEach(proxy => {
        const cleanIP = settings.cleanIPs.shift();
        if (cleanIP) proxy.server = cleanIP;
      });
    }

    if (settings.snis.length > 0 && parsed.proxies) {
      parsed.proxies.forEach(proxy => {
        const sni = settings.snis.shift();
        if (sni && ['vmess', 'vless', 'trojan'].includes(proxy.type.toLowerCase())) {
          proxy.sni = sni;
        }
      });
    }

    if (settings.enableUDP && parsed.proxies) {
      parsed.proxies.forEach(proxy => {
        if (['vmess', 'vless', 'trojan'].includes(proxy.type.toLowerCase())) {
          proxy.network = proxy.network === 'tcp' ? 'tcp' : 'udp';
        }
      });
    }

    if (settings.tlsMode !== 'none' && parsed.proxies) {
      parsed.proxies.forEach(proxy => {
        if (settings.tlsMode === 'tls') {
          proxy.tls = true;
        } else if (settings.tlsMode === 'xtls' && proxy.type.toLowerCase() === 'vless') {
          proxy.tls = true;
          proxy.flow = 'xtls-rprx-direct';
        }
      });
    }

    if (settings.fragment.enabled && parsed.proxies) {
      parsed.proxies.forEach(proxy => {
        if (['vmess', 'vless', 'trojan', 'shadowsocks'].includes(proxy.type.toLowerCase())) {
          proxy.fragment = {
            enabled: true,
            size: settings.fragment.size,
            interval: settings.fragment.interval
          };
        }
      });
    }

    if ((settings.remoteDNS.length > 0 || settings.directDNS.length > 0) && parsed.dns) {
      parsed.dns.nameserver = [
        ...settings.remoteDNS.map(dns => dns.split(',')[0]),
        ...settings.directDNS.map(dns => dns.split(',')[0])
      ];
    }

    if (parsed.dns) {
      parsed.dns.ipv6 = settings.useIPv6;
    }

    return jsYaml.dump(parsed);
  }).filter(Boolean).join('\n---\n');
}

function mergeYamlConfigs(configs, ports, settings) {
  const merged = {
    port: 7890,
    'socks-port': 7891,
    mode: 'rule',
    proxies: [],
    'proxy-groups': [],
    rules: [],
    dns: { enable: true, nameserver: [] }
  };
  const proxyNames = new Set();
  const portList = ports.split(',').map(p => p.trim());

  configs.forEach(config => {
    if (!config) return;

    if (config.proxies && Array.isArray(config.proxies)) {
      config.proxies.forEach(proxy => {
        if (!isValidProxy(proxy)) return;
        if (proxy.name && !proxyNames.has(proxy.name)) {
          if (portList.length > 0 && !portList.includes('All Ports') && proxy.port) {
            if (!portList.includes(proxy.port.toString())) return;
          }
          proxyNames.add(proxy.name);
          merged.proxies.push(proxy);
        }
      });
    }

    if (config.rules && Array.isArray(config.rules)) {
      merged.rules = [...new Set([...merged.rules, ...config.rules])];
    }

    if (config['proxy-groups'] && Array.isArray(config['proxy-groups'])) {
      merged['proxy-groups'] = [...new Set([...merged['proxy-groups'], ...config['proxy-groups']])];
    }
  });

  if (merged.dns.nameserver.length === 0 && (settings.remoteDNS.length > 0 || settings.directDNS.length > 0)) {
    merged.dns.nameserver = [
      ...settings.remoteDNS.map(dns => dns.split(',')[0]),
      ...settings.directDNS.map(dns => dns.split(',')[0])
    ];
  } else if (merged.dns.nameserver.length === 0) {
    merged.dns.nameserver = ['8.8.8.8', '1.1.1.1'];
  }
  merged.dns.ipv6 = settings.useIPv6;

  if (merged['proxy-groups'].length === 0 && merged.proxies.length > 0) {
    merged['proxy-groups'].push({
      name: 'Auto-Select',
      type: 'url-test',
      proxies: merged.proxies.map(p => p.name)
    });
  }

  return merged;
}

function isValidProxy(proxy) {
  if (!proxy || !proxy.name || !proxy.type || !proxy.server || !proxy.port) return false;
  switch (proxy.type.toLowerCase()) {
    case 'vmess':
      return !!proxy.uuid && !!proxy.cipher;
    case 'trojan':
      return !!proxy.password;
    case 'shadowsocks':
      return !!proxy.cipher && !!proxy.password;
    case 'vless':
      return !!proxy.uuid;
    default:
      return true;
  }
}

function toYamlString(obj) {
  try {
    return jsYaml.dump(obj, { indent: 2, skipInvalid: true });
  } catch (e) {
    return 'proxies: []';
  }
}

async function generateClashConfig(ports, protocol, settings) {
  const urls = [
    'https://raw.githubusercontent.com/NiREvil/vless/main/sub/clash-meta.yml',
    'https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml',
    'https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml'
  ];

  try {
    const rawConfigs = await fetchConfigs(urls, settings.remoteDNS, settings.directDNS);
    if (rawConfigs.yaml.length === 0) {
      return 'proxies: []';
    }

    let finalConfigs = rawConfigs.yaml.map(config => {
      const parsed = validateAndParseYaml(config);
      if (!parsed || !parsed.proxies) return config;

      const protocolList = protocol ? protocol.split(',').map(p => p.toLowerCase()) : settings.selectedProtocols;
      parsed.proxies = parsed.proxies.filter(proxy =>
        protocolList.includes(proxy.type.toLowerCase())
      );

      return jsYaml.dump(parsed);
    }).filter(Boolean).join('\n---\n');

    if (ports && !ports.includes('All Ports')) {
      finalConfigs = filterYamlByPorts([finalConfigs], ports.split(',').map(p => p.trim()));
    }

    finalConfigs = applyUserSettingsToYaml([finalConfigs], settings);
    return finalConfigs || 'proxies: []';
  } catch (error) {
    return 'proxies: []';
  }
}

async function generateV2rayConfig(protocol, ports, settings) {
  const rawConfigs = await fetchConfigs([    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/final.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/custom/ipv6.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/custom/udp.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/converted.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/IR.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hy2",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/config_lite.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/tuic.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/vmess.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/vless.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/reality.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/refs/heads/main/hysteria.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/ss.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/trojan.txt",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/refs/heads/main/protocols/trojan",    
     'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/vmess.txt',
    'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Config%20list10.txt',
    'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Config%20list1.txt',
    'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Config%20list11.txt',
    'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Config%20list2.txt'
  ], settings.remoteDNS, settings.directDNS);

  let configContent = '';
  const protocolList = protocol.split(',').map(p => p.toLowerCase());
  const portList = ports.split(',');

  const filterByPort = (configs) => {
    if (portList.length > 0 && !portList.includes('All Ports')) {
      return configs.filter(line => {
        const match = line.match(/@[^:]+:(\d+)/) || line.match(/port["']?\s*[:=]\s*["']?(\d+)/);
        return match && portList.includes(match[1]);
      });
    }
    return configs;
  };

  if (protocolList.includes('vmess')) {
    configContent += filterByPort(rawConfigs.vmess.map(link => processVmess(link, settings))).join('\n') + '\n';
  }
  if (protocolList.includes('vless')) {
    configContent += filterByPort(rawConfigs.vless.map(link => processVless(link, settings))).join('\n') + '\n';
  }
  if (protocolList.includes('shadowsocks')) {
    configContent += filterByPort(rawConfigs.shadowsocks.map(link => processShadowsocks(link, settings))).join('\n') + '\n';
  }
  if (protocolList.includes('trojan')) {
    configContent += filterByPort(rawConfigs.trojan.map(link => processTrojan(link, settings))).join('\n') + '\n';
  }

  return configContent.trim();
}