package daemon

// guiHTML is the self-contained local control panel served by ratelmeshd on its GUI
// address (DESIGN.md §3.4). It talks to the same local API a native tray app
// would use: poll /localapi/status, and POST exit selection. No external assets.
// The UI is bilingual (English / 简体中文): it auto-picks from the browser
// language and can be toggled; the choice persists in localStorage. All response
// data reaches the DOM via textContent only (never innerHTML), so a client-chosen
// hostname cannot inject script into the loopback GUI origin (Grok #6).
const guiHTML = `<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RatelMesh</title>
<style>
 :root{color-scheme:light dark}
 body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#111}
 @media (prefers-color-scheme:dark){body{background:#15171b;color:#e8e8e8}.card{background:#1e2127!important;box-shadow:none!important}th{background:#252932!important}}
 header{background:#b45309;color:#fff;padding:1rem 1.25rem;font-size:1.2rem;font-weight:600;display:flex;justify-content:space-between;align-items:center}
 #langsel{font:inherit;font-size:.8rem;font-weight:600;padding:.25rem .7rem;border-radius:6px;border:1px solid #fff8;background:#fff2;color:#fff;cursor:pointer}
 .wrap{max-width:820px;margin:1.25rem auto;padding:0 1rem}
 .card{background:#fff;border-radius:8px;box-shadow:0 1px 3px #0002;padding:1rem 1.25rem;margin-bottom:1rem}
 .kv{display:grid;grid-template-columns:9rem 1fr;gap:.25rem .5rem}
 .kv b{font-weight:600}
 table{border-collapse:collapse;width:100%}
 th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #8883}
 code{font-family:ui-monospace,monospace}
 select,button{font:inherit;padding:.35rem .6rem;border-radius:6px;border:1px solid #8886;background:transparent;color:inherit}
 button{cursor:pointer;background:#b45309;color:#fff;border:none}
 button:disabled,select:disabled{opacity:.45;cursor:not-allowed}
 .notice{padding:.65rem .8rem;border-radius:6px;margin-bottom:1rem;background:#dc26261a;color:#b91c1c}
 .notice[hidden]{display:none}
 .pill{border-radius:10px;padding:0 .5rem;font-size:.8rem;background:#8882}
 .direct{background:#16a34a33;color:#166534}
 .exit{background:#b4530933;color:#b45309}
 .route{font-weight:700;padding:.7rem .8rem;border-radius:7px;margin-bottom:.8rem;background:#16a34a1c}
 button.selected{background:#15803d;box-shadow:0 0 0 2px #15803d44}
</style></head><body>
<header><span>🦡 RatelMesh</span><select id="langsel" onchange="setLanguage(this.value)"><option value="system">System</option><option value="zh">简体中文</option><option value="en">English</option></select></header>
<div class="wrap">
 <div id="notice" class="notice" role="status" aria-live="polite" hidden></div>
 <div class="card"><div class="kv" id="summary"></div></div>
 <div class="card">
  <div id="route" class="route" role="status" aria-live="polite"></div>
  <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:.75rem">
   <b id="exitlabel"></b>
   <select id="exitsel"></select>
   <button id="btnuse" onclick="useExit()"></button>
   <button id="btndirect" onclick="clearExit()" style="background:#6b7280"></button>
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
  <div style="margin-top:.5rem;color:#6b7280">
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
