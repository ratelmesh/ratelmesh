package daemon

// guiHTML is the self-contained local control panel served by ratelmeshd on its GUI
// address (DESIGN.md §3.4). It talks to the same local API a native tray app
// would use: poll /localapi/status, and POST exit selection. No external assets.
// The UI is bilingual (English / 简体中文): it auto-picks from the browser
// language and can be toggled; the choice persists in localStorage. All response
// data reaches the DOM via textContent only (never innerHTML), so a client-chosen
// hostname cannot inject script into the loopback GUI origin.
const guiHTML = `<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RatelMesh</title>
<style>
 :root{color-scheme:dark;--ink:#f4f7f9;--muted:#9aabb5;--panel:#111820;--line:#27333d;--cyan:#20b9e8;--healthy:#16956c;--warning:#d8902f;--critical:#ffb4ab}
 *{box-sizing:border-box}
 body{font:14px/1.5 system-ui,sans-serif;margin:0;min-height:100vh;background:radial-gradient(circle at 78% -10%,#123647 0,transparent 38%),#0b0f14;color:var(--ink)}
 header{border-bottom:1px solid var(--line);background:#0b0f14e8;backdrop-filter:blur(16px);padding:.8rem max(1rem,calc((100vw - 820px)/2 + 1rem));display:flex;justify-content:space-between;align-items:center}
 .brand{display:flex;align-items:center;gap:.65rem;font-size:1.15rem;font-weight:720;letter-spacing:-.02em}
 .brand svg{width:34px;height:34px;display:block}
 #langsel{font:inherit;font-size:.8rem;font-weight:650;padding:.35rem .7rem;border-radius:999px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}
 #langsel:focus-visible,button:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid var(--cyan);outline-offset:2px}
 .wrap{max-width:820px;margin:1.25rem auto;padding:0 1rem}
 .card{background:#111820e8;border:1px solid var(--line);border-radius:14px;box-shadow:0 18px 48px #0005;padding:1rem 1.25rem;margin-bottom:1rem}
 .kv{display:grid;grid-template-columns:9rem 1fr;gap:.25rem .5rem}
 .kv b{font-weight:600}
 table{border-collapse:collapse;width:100%}
 th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line)}
 th{color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.07em}
 code{font-family:ui-monospace,monospace}
 select,button{font:inherit;padding:.4rem .7rem;border-radius:8px;border:1px solid var(--line);background:#0b0f14;color:inherit}
 button{cursor:pointer;background:var(--cyan);color:#0b0f14;border:none;font-weight:700}
 button:disabled,select:disabled{opacity:.45;cursor:not-allowed}
 .notice{padding:.65rem .8rem;border:1px solid #a22619;border-radius:8px;margin-bottom:1rem;background:#a2261926;color:var(--critical)}
 .notice[hidden]{display:none}
 .pill{border:1px solid var(--line);border-radius:999px;padding:.1rem .55rem;font-size:.78rem;background:#27333d}
 .direct{border-color:#16956c66;background:#16956c26;color:#a8e7c9}
 .exit{border-color:#20b9e866;background:#20b9e826;color:#a8e7f7}
 .route{font-weight:700;padding:.75rem .85rem;border:1px solid #20b9e866;border-radius:10px;margin-bottom:.8rem;background:#20b9e815;color:#a8e7f7}
 button.selected{background:var(--healthy);color:#fff;box-shadow:0 0 0 2px #16956c55}
 a{color:#66d3f2}
 @media(max-width:620px){.kv{grid-template-columns:7rem minmax(0,1fr)}table{display:block;max-width:100%;overflow-x:auto;white-space:nowrap}.route+div{flex-wrap:wrap}header{padding:.7rem 1rem}}
</style></head><body>
<header><span class="brand"><svg viewBox="0 0 512 512" role="img" aria-label="RatelMesh honey badger Mesh mark"><path fill="#0B0F14" stroke="#42515C" stroke-width="8" d="M81 131C61 113 46 112 34 124 18 140 25 171 54 189l19 167c5 48 32 78 74 101l89 39q20 9 40 0l89-39c42-23 69-53 74-101l19-167c29-18 36-49 20-65-12-12-27-11-47 7l-70-45c-32-21-67-32-105-32s-73 11-105 32z"/><path fill="#F4F7F9" d="M73 145c-12-11-21-13-27-7-8 8-2 24 14 34l17 10 20-29zm366 0c12-11 21-13 27-7 8 8 2 24-14 34l-17 10-20-29zM91 142c45-47 99-70 165-70s120 23 165 70l-37 65c-42-22-85-33-128-33s-86 11-128 33zM128 207l34 30 25 156-58-43-22-92zm256 0-34 30-25 156 58-43 22-92zM231 333l25-20 25 20-9 41 18 25-34 20-34-20 18-25z"/><g fill="none" stroke="#20B9E8" stroke-linecap="round" stroke-linejoin="round" stroke-width="4"><path d="M180 120h152m-172 40h192"/><path d="m180 120-20 40m20-40 76 40m0-40-96 40m96-40 96 40m-20-40-76 40m76-40 20 40"/></g><path fill="#20B9E8" d="m146 276 66 15-32 23-38-12zm220 0-66 15 32 23 38-12z"/><path fill="#0B0F14" d="m232 395 24-9 24 9-10 16-14 6-14-6z"/><g fill="#20B9E8"><circle cx="180" cy="120" r="7"/><circle cx="256" cy="120" r="7"/><circle cx="332" cy="120" r="7"/><circle cx="160" cy="160" r="7"/><circle cx="256" cy="160" r="7"/><circle cx="352" cy="160" r="7"/></g></svg>RatelMesh</span><select id="langsel" onchange="setLanguage(this.value)"><option value="system">System</option><option value="zh">简体中文</option><option value="en">English</option></select></header>
<div class="wrap">
 <div id="notice" class="notice" role="status" aria-live="polite" hidden></div>
 <div class="card"><div class="kv" id="summary"></div></div>
 <div class="card">
  <div id="route" class="route" role="status" aria-live="polite"></div>
  <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:.75rem">
   <b id="exitlabel"></b>
   <select id="exitsel"></select>
   <button id="btnuse" onclick="useExit()"></button>
   <button id="btndirect" onclick="clearExit()" style="background:#27333d;color:#f4f7f9"></button>
  </div>
  <table id="peers"><thead><tr>
   <th id="h_ip"></th><th id="h_name"></th><th id="h_role"></th><th id="h_path"></th><th id="h_online"></th>
  </tr></thead><tbody></tbody></table>
 </div>
 <div class="card" id="exitclientcard" hidden>
  <b id="exitclienttitle"></b>
  <div id="exitclients"></div>
 </div>
 <div class="card">
  <div style="display:flex;gap:.75rem;align-items:center">
   <b id="doctortitle"></b>
   <button id="doctorbutton" onclick="runDoctor()"></button>
  </div>
  <div style="margin-top:.5rem;color:#9aabb5">
   <span id="doctorprivacy"></span>
   <a id="doctorprivacylink" href="/privacy" target="_blank" rel="noopener noreferrer"></a>
  </div>
  <div id="doctorresult" style="margin-top:.75rem" role="status" aria-live="polite"></div>
  <div id="doctorrepairs" style="display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.75rem"></div>
 </div>
</div>
<script>
var I18N={
 en:{state:'State',self:'Self',exit:'Exit',ks:'Kill switch',dns:'DNS',netmap:'Netmap',
  none:'none (direct)',armed:'ARMED',off:'off',peers:'peer(s)',system:'system',currentroute:'Current route',directactive:'DIRECT',exitactive:'EXIT verified · {exit}',switchdirect:'Switching to DIRECT…',switchexit:'Connecting to EXIT · {exit}…',verifyexit:'EXIT selected; verifying traffic · {exit}…',
  exitclients:'Devices using this EXIT',verified:'Verified',connecting:'Connecting',offline:'Offline',
  exitnode:'Exit node:',use:'Use',direct:'Direct',unreachable:'Cannot reach the local daemon. Retrying…',actionfail:'The change failed.',noexits:'No exits available',
  doctor:'Network Doctor',rundoctor:'Run diagnostics',doctorworking:'Checking network paths…',doctorok:'All checks passed',doctorissues:'{n} finding(s); worst: {severity}',repair:'Repair: {title}',confirmrepair:'Apply this local repair? RatelMesh will verify the result and roll back when possible.',repairdone:'Repair finished. Running diagnostics again…',
  doctorprivacy:'Active diagnostics contact your configured Coordinator, Relays and DNS resolver, Cloudflare reachability endpoints, and RatelMesh or tenant media canaries. Their operators may see the diagnostic time and your source or EXIT IP; shared reports redact these values.',doctorprivacylink:'Privacy details',doctorconsent:'Run active network diagnostics now? Your configured infrastructure, DNS resolver, Cloudflare reachability endpoints, and RatelMesh or tenant media canaries may receive the diagnostic time and your source or EXIT IP. Shared reports redact these values.',
  h_ip:'Mesh IP',h_name:'Name',h_role:'Role',h_path:'Path',h_online:'Online'},
 zh:{state:'状态',self:'本机',exit:'出口',ks:'断网开关',dns:'DNS',netmap:'网络图',
  none:'无(直连)',armed:'已开启',off:'关闭',peers:'个节点',system:'系统默认',currentroute:'当前线路',directactive:'DIRECT 直连',exitactive:'EXIT 已验证 · {exit}',switchdirect:'正在切换到 DIRECT…',switchexit:'正在连接 EXIT · {exit}…',verifyexit:'已选择 EXIT，正在验证流量 · {exit}…',
  exitclients:'正在使用本机出口的设备',verified:'已验证',connecting:'正在连接',offline:'离线',
  exitnode:'出口节点:',use:'使用',direct:'直连',unreachable:'暂时连不上本地服务，正在重试…',actionfail:'切换失败。',noexits:'暂无出口节点',
  doctor:'网络医生',rundoctor:'一键诊断',doctorworking:'正在检查网络路径…',doctorok:'全部检查通过',doctorissues:'发现 {n} 项；最高级别：{severity}',repair:'修复：{title}',confirmrepair:'确定执行这项本机修复吗？RatelMesh 会验证结果，并在可行时回滚。',repairdone:'修复执行完毕，正在重新诊断…',
  doctorprivacy:'主动诊断会连接已配置的 Coordinator、Relay 和 DNS 解析器、Cloudflare 连通性端点，以及 RatelMesh 或租户媒体探测服务。相应运营方可能看到诊断时间和你的源 IP 或 EXIT IP；分享报告会隐藏这些信息。',doctorprivacylink:'隐私说明',doctorconsent:'现在运行主动网络诊断吗？已配置的基础设施、DNS 解析器、Cloudflare 连通性端点，以及 RatelMesh 或租户媒体探测服务可能收到诊断时间和你的源 IP 或 EXIT IP。分享报告会隐藏这些信息。',
  h_ip:'Mesh IP',h_name:'名称',h_role:'角色',h_path:'路径',h_online:'在线'}
};
var ENUM={
 role:{plain:{zh:'普通'},exit:{zh:'出口'},'subnet-router':{zh:'子网路由'}},
 path:{direct:{zh:'直连'},relay:{zh:'中转'},exit:{zh:'出口'}},
 state:{Running:{zh:'运行中'},Starting:{zh:'启动中'},Stopped:{zh:'已停止'}}
};
function storageGet(key){try{return localStorage.getItem(key);}catch(e){return null;}}
function storageSet(key,value){try{localStorage.setItem(key,value);return true;}catch(e){return false;}}
var storedLanguage=storageGet('ratelmeshlang');
var LANG_PREF=storedLanguage==='zh'||storedLanguage==='en'||storedLanguage==='system'?storedLanguage:'system';
var LANG=LANG_PREF==='system'?((navigator.language||'en').toLowerCase().indexOf('zh')===0?'zh':'en'):LANG_PREF;
var DOCTOR_DISCLOSURE_VERSION='v1';
var lastStatus=null,pendingExit=null;
function T(k){return I18N[LANG][k]||k;}
function E(kind,v){var m=ENUM[kind];if(m&&m[v]&&m[v][LANG])return m[v][LANG];return v;}
function setLanguage(value){if(value!=='system'&&value!=='zh'&&value!=='en')value='system';LANG_PREF=value;storageSet('ratelmeshlang',value);LANG=value==='system'?((navigator.language||'en').toLowerCase().indexOf('zh')===0?'zh':'en'):value;renderStatic();if(lastStatus)renderRoute(lastStatus);refresh();}
function notice(msg){var n=document.getElementById('notice');n.textContent=msg||'';n.hidden=!msg;}
function renderStatic(){
 document.documentElement.lang=LANG==='zh'?'zh':'en';
 document.getElementById('langsel').value=LANG_PREF;
 document.getElementById('exitlabel').textContent=T('exitnode');
 document.getElementById('btnuse').textContent=T('use');
 document.getElementById('btndirect').textContent=T('direct');
 document.getElementById('exitclienttitle').textContent=T('exitclients');
 document.getElementById('doctortitle').textContent=T('doctor');
 document.getElementById('doctorbutton').textContent=T('rundoctor');
 document.getElementById('doctorprivacy').textContent=T('doctorprivacy')+' ';
 document.getElementById('doctorprivacylink').textContent=T('doctorprivacylink');
 ['h_ip','h_name','h_role','h_path','h_online'].forEach(function(id){document.getElementById(id).textContent=T(id);});
}
function renderRoute(s){
 var reported=s.selectedExit||s.activeExit||'';
 var shown=pendingExit===null?reported:pendingExit;
 var connecting=pendingExit!==null||(!s.activeExit&&!!s.selectedExit)||(!!s.activeExit&&!s.exitTrafficVerified);
 var text=connecting?(shown?(s.activeExit?T('verifyexit'):T('switchexit')).replace('{exit}',shown):T('switchdirect')):(T('currentroute')+': '+(shown?T('exitactive').replace('{exit}',shown):T('directactive')));
 document.getElementById('route').textContent=text;
 var use=document.getElementById('btnuse'),direct=document.getElementById('btndirect'),selected=document.getElementById('exitsel').value;
 use.classList.toggle('selected',!!shown&&shown===selected);direct.classList.toggle('selected',!shown);
 use.setAttribute('aria-pressed',!!shown&&shown===selected?'true':'false');direct.setAttribute('aria-pressed',!shown?'true':'false');
}
var refreshing=false;
async function refresh(){
 if(refreshing)return; refreshing=true;
 try{
 var res=await fetch('/localapi/status',{cache:'no-store'});if(!res.ok)throw new Error('status '+res.status);var s=await res.json();lastStatus=s;notice('');
 var sum=document.getElementById('summary'); sum.textContent='';
 var row=function(k,v){var b=document.createElement('b');b.textContent=k;var sp=document.createElement('span');sp.textContent=v;sum.appendChild(b);sum.appendChild(sp);};
 row(T('state'),E('state',s.state));
 row(T('self'),(s.self.meshIP||'')+' '+(s.self.name||''));
 row(T('exit'),s.activeExit?(s.exitTrafficVerified?T('exitactive'):T('verifyexit')).replace('{exit}',s.activeExit):(s.selectedExit?T('switchexit').replace('{exit}',s.selectedExit):T('none')));
 row(T('ks'),s.killSwitch?T('armed'):T('off'));
 row(T('dns'),s.dns||T('system'));
 row(T('netmap'),'v'+s.netmapVersion+', '+(s.peers?s.peers.length:0)+' '+T('peers'));
 var tb=document.querySelector('#peers tbody'); tb.textContent='';
 var sel=document.getElementById('exitsel'); var cur=sel.value; sel.textContent='';
 var cell=function(txt,code){var td=document.createElement('td');if(code){var c=document.createElement('code');c.textContent=txt;td.appendChild(c);}else{td.textContent=txt;}return td;};
 (s.peers||[]).forEach(function(p){
  var tr=document.createElement('tr');
  tr.appendChild(cell(p.meshIP||'',true));
  tr.appendChild(cell(p.name||'',false));
  tr.appendChild(cell(E('role',p.role||''),false));
  var tdPath=document.createElement('td');
  if(p.pathType&&p.pathType!=='-'){var sp=document.createElement('span');sp.className='pill '+(p.pathType==='direct'?'direct':(p.pathType==='exit'?'exit':''));sp.textContent=E('path',p.pathType);tdPath.appendChild(sp);}
  tr.appendChild(tdPath);
  tr.appendChild(cell(p.online?'●':'○',false));
  tb.appendChild(tr);
  if(p.role==='exit'){var o=document.createElement('option');o.value=p.name;o.textContent=p.name+' ('+p.meshIP+')';sel.appendChild(o);}
 });
 if(cur)sel.value=cur;if(!sel.value&&sel.options.length)sel.selectedIndex=0;
 if(!sel.options.length){var empty=document.createElement('option');empty.textContent=T('noexits');empty.value='';sel.appendChild(empty);}
 sel.disabled=!sel.value;document.getElementById('btnuse').disabled=!sel.value;
 var exitCard=document.getElementById('exitclientcard'),exitList=document.getElementById('exitclients');exitList.textContent='';
 (s.exitClients||[]).forEach(function(client){var line=document.createElement('div');line.className='kv';var name=document.createElement('b');name.textContent=client.name||client.meshIP||'-';var state=document.createElement('span');state.textContent=client.state==='active'?T('verified'):(client.state==='offline'?T('offline'):T('connecting'));line.appendChild(name);line.appendChild(state);exitList.appendChild(line);});
 exitCard.hidden=!(s.exitClients||[]).length;
 renderRoute(s);
 }catch(e){notice(T('unreachable'));}finally{refreshing=false;}
}
async function mutate(url,target){pendingExit=target;if(lastStatus)renderRoute(lastStatus);try{var r=await fetch(url,{method:'POST'});if(!r.ok)throw new Error(await r.text());pendingExit=null;await refresh();}catch(e){pendingExit=null;if(lastStatus)renderRoute(lastStatus);notice(T('actionfail')+' '+e.message);}}
async function useExit(){var n=document.getElementById('exitsel').value;if(n)await mutate('/localapi/exit/use?name='+encodeURIComponent(n),n);}
async function clearExit(){await mutate('/localapi/exit/clear','');}
async function runDoctor(){
 var result=document.getElementById('doctorresult'),repairs=document.getElementById('doctorrepairs'),button=document.getElementById('doctorbutton');
 var consented=storageGet('ratelmeshdoctorconsent')===DOCTOR_DISCLOSURE_VERSION;
 if(!consented){
  if(!window.confirm(T('doctorconsent')))return;
  storageSet('ratelmeshdoctorconsent',DOCTOR_DISCLOSURE_VERSION);
 }
 button.disabled=true;result.textContent=T('doctorworking');repairs.textContent='';
 try{
  var response=await fetch('/localapi/doctor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,disclosureVersion:DOCTOR_DISCLOSURE_VERSION}),cache:'no-store'});if(!response.ok)throw new Error('status '+response.status);
  var data=await response.json(),summary=data.report&&data.report.summary?data.report.summary:{};
  result.textContent=summary.ok?T('doctorok'):T('doctorissues').replace('{n}',summary.total_findings||0).replace('{severity}',summary.worst_severity||'-');
  (data.report&&data.report.findings||[]).forEach(function(f){var line=document.createElement('div');line.textContent=(f.code||'')+': '+(f.summary||'');result.appendChild(line);});
  var available={};(data.availableRepairs||[]).forEach(function(action){available[action]=true;});
  (data.plan&&data.plan.repairs||[]).forEach(function(repair){if(!repair.applicable||!available[repair.action])return;var b=document.createElement('button');b.textContent=T('repair').replace('{title}',repair.title||repair.action);b.onclick=function(){repairDoctor(repair.action);};repairs.appendChild(b);});
 }catch(e){result.textContent=T('actionfail')+' '+e.message;}finally{button.disabled=false;}
}
async function repairDoctor(action){
 if(!window.confirm(T('confirmrepair')))return;
 var result=document.getElementById('doctorresult');
 try{var response=await fetch('/localapi/doctor/repair',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action,confirm:true,disclosureVersion:DOCTOR_DISCLOSURE_VERSION})});if(!response.ok)throw new Error(await response.text());result.textContent=T('repairdone');await runDoctor();}catch(e){result.textContent=T('actionfail')+' '+e.message;}
}
renderStatic(); refresh(); setInterval(refresh,2000);
</script>
</body></html>`
