package daemon

// privacyHTML is a local-only geographic privacy checklist. It does not collect
// browser data: the WebRTC candidate test runs entirely in the page and uses
// RatelMesh's own STUN endpoint only to reveal which public address the
// browser would expose to a real-time communications site.
const privacyHTML = `<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RatelMesh — Location Privacy</title>
<style>
:root{color-scheme:dark;font:15px/1.55 system-ui,sans-serif;--ink:#f4f7f9;--muted:#9aabb5;--panel:#111820;--line:#27333d;--cyan:#20b9e8;--warning:#d8902f}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 78% -10%,#123647 0,transparent 38%),#0b0f14;color:var(--ink)}.wrap{max-width:820px;margin:auto;padding:24px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px}
h1{font-size:1.65rem;margin:0;letter-spacing:-.025em}h2{font-size:1.08rem;margin:.1rem 0 .55rem}.sub,.muted{color:var(--muted)}.sub{margin:.25rem 0 0}.warn{color:var(--warning)}
.card{background:#111820e8;border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin:12px 0;box-shadow:0 18px 48px #0005}
.row{display:flex;align-items:flex-start;gap:10px}.mark{font-size:1.15rem;line-height:1.5}
button{font:inherit;border:0;border-radius:8px;padding:8px 13px;background:var(--cyan);color:#0b0f14;font-weight:700;cursor:pointer}
button.secondary{background:#27333d;color:var(--ink)}button:focus-visible,a:focus-visible{outline:3px solid var(--cyan);outline-offset:2px}code{font-family:ui-monospace,monospace;word-break:break-all}
ul{margin:.4rem 0 .1rem;padding-left:1.25rem}li{margin:.35rem 0}.result{padding:10px;border:1px solid var(--line);background:#0b0f14;border-radius:8px;white-space:pre-wrap;min-height:24px}
a{color:#66d3f2}#lang{min-width:62px}@media(max-width:620px){.wrap{padding:18px 16px}header{align-items:flex-start}.card{padding:15px}}
</style></head><body><div class="wrap">
<header><div><h1 id="title"></h1><p class="sub" id="subtitle"></p></div><button id="lang" class="secondary"></button></header>
<div class="card"><h2 id="networkTitle"></h2><div id="networkStatus" class="result"></div><p class="muted" id="networkHelp"></p></div>
<div class="card"><h2 id="locationTitle"></h2><ul id="locationList"></ul></div>
<div class="card"><h2 id="browserTitle"></h2><ul id="browserList"></ul></div>
<div class="card"><h2 id="radioTitle"></h2><ul id="radioList"></ul></div>
<div class="card"><h2 id="webrtcTitle"></h2><p id="webrtcHelp"></p><button id="testWebRTC"></button><div id="webrtcResult" class="result" style="margin-top:10px"></div></div>
<div class="card"><h2 id="limitsTitle"></h2><p id="limits"></p></div>
</div><script>
const C={
 en:{title:'Geographic privacy',subtitle:'Prevent accidental disclosure of your physical location and direct network address.',lang:'中文',
 networkTitle:'1. RatelMesh network protection',checking:'Checking local tunnel status…',direct:'No exit is active. Websites can see the current network address.',connecting:'Connecting to exit {exit}. Traffic is not using it yet.',protected:'Exit: {exit}\nIPv4/IPv6 fail-closed protection: ON',unprotected:'An exit is selected, but fail-closed protection is not armed.',networkHelp:'RatelMesh captures IPv4, IPv6 and DNS while an exit is active. If the exit has no native IPv6 service, IPv6 is blocked rather than sent through the local network.',
 locationTitle:'2. System location services',location:['macOS: System Settings → Privacy & Security → Location Services. Disable the global switch or remove permission from browsers and apps that do not need location.','iPhone/iPad: Settings → Privacy & Security → Location Services. Prefer “Never”, “Ask Next Time”, or approximate location for non-navigation apps.','Turning off location can break maps, device recovery and other location-dependent features. Review permissions instead of changing them blindly.'],
 browserTitle:'3. Browser and advertising privacy',browser:['Chrome: Settings → Privacy and security → Site settings → Location → do not allow sites by default.','Safari: Safari → Settings → Websites → Location; set untrusted sites to Deny. Enable Prevent cross-site tracking in Safari Privacy settings.','Brave: use brave://settings/content/location and review WebRTC IP handling. Tor Browser is appropriate only when its slower, separate anonymity model matches your threat level.','Modern Apple systems do not offer a useful “periodic advertising ID reset” workflow. Disable personalized ads and review per-app tracking permissions instead.'],
 radioTitle:'4. Wi-Fi and Bluetooth-assisted location',radio:['macOS: Location Services → System Services → Details → review Networking & Wireless and location-based suggestions. Disabling them may affect Wi-Fi, AirDrop and nearby-device features.','Android: Settings → Location → Location services → turn off Wi-Fi scanning and Bluetooth scanning when your threat model requires it.','Bluetooth-off alone does not guarantee location privacy; applications can still infer location from IP address, account history or other sensors.'],
 webrtcTitle:'5. Local WebRTC leak test',webrtcHelp:'This test contacts stun.ratelmesh.com and displays ICE candidates only in this page. A public candidate should be the exit address, never the local ISP address.',test:'Run WebRTC test',notSupported:'WebRTC is unavailable or disabled in this browser.',running:'Collecting candidates…',none:'No address candidates were exposed. WebRTC may be restricted.',
 limitsTitle:'What RatelMesh cannot change silently',limits:'Operating systems intentionally require user consent for Location Services, browser permissions, advertising controls, Wi-Fi scanning and Bluetooth. RatelMesh opens or explains these settings; it never changes privacy permissions behind the user’s back.'},
 zh:{title:'地理位置隐私',subtitle:'防止实际物理位置和本地公网地址被意外泄露。',lang:'EN',
 networkTitle:'1. RatelMesh 网络保护',checking:'正在检查本地隧道状态…',direct:'当前未使用出口。网站可以看到所在网络的公网地址。',connecting:'正在连接出口 {exit}，流量尚未经过该出口。',protected:'出口：{exit}\nIPv4/IPv6 断网保护：已开启',unprotected:'已经选择出口，但断网保护尚未开启。',networkHelp:'使用出口时，RatelMesh 会接管 IPv4、IPv6 和 DNS。如果出口没有原生 IPv6，IPv6 会被阻断，不会改走本地网络。',
 locationTitle:'2. 系统定位服务',location:['macOS：系统设置 → 隐私与安全性 → 定位服务。可以关闭总开关，或撤销不需要定位的浏览器和应用权限。','iPhone/iPad：设置 → 隐私与安全性 → 定位服务。非导航应用优先选择“永不”“下次询问”或模糊位置。','关闭定位可能影响地图、设备找回及其他功能。建议逐项检查权限，不要盲目关闭。'],
 browserTitle:'3. 浏览器与广告隐私',browser:['Chrome：设置 → 隐私和安全 → 网站设置 → 位置信息，默认设为不允许网站获取位置。','Safari：Safari → 设置 → 网站 → 位置，对不可信网站设为拒绝；并在隐私设置中开启“防止跨网站跟踪”。','Brave：打开 brave://settings/content/location，并检查 WebRTC IP 处理策略。只有在能够接受速度和兼容性影响时才使用 Tor Browser。','现代 Apple 系统不再适合“定期重置广告 ID”。应关闭个性化广告并检查各应用的跟踪权限。'],
 radioTitle:'4. Wi-Fi 与蓝牙辅助定位',radio:['macOS：定位服务 → 系统服务 → 详细信息，检查“网络与无线”和基于位置的建议。关闭后可能影响 Wi-Fi、AirDrop 和附近设备功能。','Android：设置 → 位置信息 → 位置信息服务；按风险需要关闭 Wi-Fi 扫描和蓝牙扫描。','只关闭蓝牙不能保证位置隐私；应用仍可能通过公网 IP、账号历史或其他传感器推断位置。'],
 webrtcTitle:'5. 本地 WebRTC 泄漏测试',webrtcHelp:'测试只连接 stun.ratelmesh.com，ICE 地址只显示在本页面。公网候选地址应属于出口，不能是当地运营商地址。',test:'运行 WebRTC 测试',notSupported:'此浏览器未提供 WebRTC，或已将其禁用。',running:'正在收集候选地址…',none:'没有暴露地址候选；WebRTC 可能已受限制。',
 limitsTitle:'RatelMesh 不能静默修改的设置',limits:'操作系统要求用户亲自授权定位服务、浏览器权限、广告控制、Wi-Fi 扫描和蓝牙。RatelMesh 会提供检查和设置指引，但不会在用户不知情时修改隐私权限。'}
};
let lang=(localStorage.getItem('ratelmeshPrivacyLang')||navigator.language||'en').toLowerCase().startsWith('zh')?'zh':'en';
const ids=['title','subtitle','networkTitle','networkHelp','locationTitle','browserTitle','radioTitle','webrtcTitle','webrtcHelp','limitsTitle','limits'];
function render(){const t=C[lang];document.documentElement.lang=lang;ids.forEach(id=>document.getElementById(id).textContent=t[id]);document.getElementById('lang').textContent=t.lang;document.getElementById('testWebRTC').textContent=t.test;fill('locationList',t.location);fill('browserList',t.browser);fill('radioList',t.radio);checkStatus();}
function fill(id,items){const ul=document.getElementById(id);ul.textContent='';items.forEach(v=>{const li=document.createElement('li');li.textContent=v;ul.appendChild(li);});}
document.getElementById('lang').onclick=()=>{lang=lang==='zh'?'en':'zh';localStorage.setItem('ratelmeshPrivacyLang',lang);render();};
async function checkStatus(){const box=document.getElementById('networkStatus'),t=C[lang];box.textContent=t.checking;try{const r=await fetch('/localapi/status',{cache:'no-store'});if(!r.ok)throw 0;const s=await r.json();box.textContent=s.activeExit?(s.killSwitch?t.protected.replace('{exit}',s.activeExit):t.unprotected):(s.selectedExit?t.connecting.replace('{exit}',s.selectedExit):t.direct);}catch(_){box.textContent=t.unprotected;}}
document.getElementById('testWebRTC').onclick=async()=>{const out=document.getElementById('webrtcResult'),t=C[lang];out.textContent=t.running;if(!window.RTCPeerConnection){out.textContent=t.notSupported;return;}const found=new Set();let pc;try{pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.ratelmesh.com:3479'}]});pc.createDataChannel('privacy-test');pc.onicecandidate=e=>{if(e.candidate&&e.candidate.candidate)found.add(e.candidate.candidate);};await pc.setLocalDescription(await pc.createOffer());await new Promise(r=>setTimeout(r,3500));out.textContent=found.size?[...found].join('\n'):t.none;}catch(_){out.textContent=t.notSupported;}finally{if(pc)pc.close();}};
render();
</script></body></html>`
