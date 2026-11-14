/* KARTIKA-SENTINEL — antarmuka & simulasi waktu nyata */
'use strict';
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const ICON = { cloud: '🌐', firewall: '🛡️', server: '🖥️', sentinel: '🦅', workstation: '💻', ap: '📶', plc: '⚙️', ups: '🔋', nvr: '📼', camera: '📹', access: '🚪', radio: '📻' };

const RULE_ICON = { BRUTE_FORCE: '🔑', BF_SUCCESS: '🔓', PORT_SCAN: '📡', MODBUS_WRITE: '⚙️', MODBUS_RECON: '🔍', OT_IMPACT: '⚡', MAL_DOC: '📄', DNS_TUNNEL: '🕳️',
  C2_BEACON: '📶', IOC_MATCH: '☠️', IOC_SCAN: '☠️', LATERAL_SMB: '↔️', RANSOMWARE: '🔐', DDOS_OUT: '🌊', ROGUE_DEVICE: '📱', ARP_SPOOF: '🎭', AI: '🧠' };
const HUBS = { it: { id: 'SW-IT', x: 440, y: 145 }, ot: { id: 'SW-OT', x: 700, y: 145 } };

let MODEL = null, eng, simT, prevSimT, lastTickPerf = 0, queue, running, blockedCount, selInc = null, lastRender = 0, flows = [], scenTotal = {};
let hist = { epm: [], post: [], al: [] };
const S = { speed: 2 };

function reset() {
  eng = new DetectionEngine({ model: MODEL, onAlert });
  simT = 0; prevSimT = 0; queue = []; running = new Set(); blockedCount = 0; selInc = null; flows = []; scenTotal = {}; hist = { epm: [], post: [], al: [] };
  renderTopoStatic();
  $('#feed').innerHTML = '<div class="empty">Belum ada ancaman. Jalankan skenario latihan di bawah untuk menguji deteksi.</div>';
  $('#evlog').innerHTML = ''; renderAll(true);
}

/* ---------- loop simulasi ---------- */
function tick() {
  const dt = 0.25 * S.speed; const t1 = simT + dt;
  const batch = normalTraffic(simT, dt);
  while (queue.length && queue[0].ts <= t1) batch.push(queue.shift());
  batch.sort((a, b) => a.ts - b.ts);
  for (const e of batch) {
    eng.ingest(e);
    if (e.blocked) blockedCount++;
    if (e.src !== e.dst) flows.push({ e, until: t1 + 1.5 });
    logEvent(e);
  }
  prevSimT = simT; simT = t1; lastTickPerf = performance.now(); eng.windowTick(simT);
  flows = flows.filter(f => f.until > simT).slice(-70);
  for (const id of [...running]) if (!queue.some(e => e.scen === id)) { running.delete(id); }
  renderClock();
  if (performance.now() - lastRender > 600) { renderAll(); lastRender = performance.now(); }
}
function runScenario(id) {
  const sc = SCENARIOS.find(s => s.id === id); if (running.has(id)) return;
  const evs = sc.build(simT + 0.5); evs.forEach(e => e.scen = id); scenTotal[id] = evs.length;
  queue.push(...evs); queue.sort((a, b) => a.ts - b.ts); running.add(id); renderScen();
}

/* ---------- alert handler ---------- */
function onAlert(a) {
  const f = $('#feed'); if (f.querySelector('.empty')) f.innerHTML = '';
  f.insertAdjacentHTML('afterbegin', alertHtml(a));
  while (f.children.length > 60) f.lastChild.remove();
  if (SEV[a.sev] >= 4) {
    toast(`<b>${SEV_LABEL[4]}</b> · ${esc(a.title)}`);
    if ($('#autoResp').checked) autoRespond(a);
  }
}
function alertHtml(a) {
  const v = SEV[a.sev]; const isAI = a.rule.startsWith('AI_');
  return `<div class="al v${v}"><span class="aic">${RULE_ICON[isAI ? 'AI' : a.rule] || '•'}</span><div class="m"><span class="sev s${v}">${SEV_LABEL[v]}</span><span class="time">${wib(a.ts)}</span><span class="time">${a.id} · ${a.incident || ''}</span></div>
  <div class="t">${esc(a.title)}</div><div class="d">${esc(a.detail)}</div>
  <div class="m">${a.techs.map(t => `<span class="tt ${MITRE[t].dom === 'ICS' ? 'ics' : ''}" title="${esc(MITRE[t].name)}">${t}</span>`).join('')}${isAI ? '<span class="tt ai">AI · Isolation Forest</span>' : ''}</div></div>`;
}
function toast(html) {
  const d = document.createElement('div'); d.className = 'toast'; d.innerHTML = html; $('#toasts').appendChild(d);
  setTimeout(() => d.remove(), 4500); while ($('#toasts').children.length > 3) $('#toasts').firstChild.remove();
}
function logEvent(e) {
  if (e.proto === 'rtsp' || (rnd() < 0.55 && !e.scen && !e.blocked)) return;
  const el = $('#evlog'); const d = document.createElement('div');
  const s = e.srcIp || ASSET_BY_ID[e.src]?.ip || e.src, t = e.dstIp || ASSET_BY_ID[e.dst]?.ip || e.dst;
  let info = e.type === 'modbus' ? `FC${e.fc}${e.reg ? ' reg=' + e.reg : ''}` : e.query ? 'q=' + e.query : e.user ? `${e.type} user=${e.user}` : e.share ? 'share=' + e.share : e.detail || e.type;
  d.textContent = `${wib(e.ts)} ${e.proto.toUpperCase().padEnd(8)} ${s} → ${t}:${e.port} ${info}${e.blocked ? '  [DIBLOK: ' + e.blocked + ']' : ''}`;
  d.className = e.blocked ? 'blk' : e.scen ? 'bad' : '';
  el.prepend(d); while (el.children.length > 26) el.lastChild.remove();
}

/* ---------- respons ---------- */
function act(inc, kind, target) {
  const now = simT; let text = '';
  if (kind === 'iso') { eng.isolated.add(target); text = `Host ${target} (${ASSET_BY_ID[target].ip}) diisolasi dari jaringan melalui switch/NAC.`; }
  if (kind === 'blk') { eng.blockedIps.add(target); text = `IP ${target} diblokir pada firewall FW-01 (aturan masuk & keluar).`; }
  if (kind === 'cred') { text = `Kredensial akun ${target} di-reset dan sesi aktif dicabut pada Domain Controller.`; }
  if (kind === 'plc') { eng.plcLocked = true; text = `PLC-GENSET dikunci ke mode RUN-LOCK; firewall Modbus hanya mengizinkan WS-ENG. Parameter dikembalikan ke baseline.`; }
  if (kind === 'close') { inc.status = 'Terkendali'; text = 'Insiden dinyatakan TERKENDALI oleh Perwira Siber.'; }
  if (inc.actions.some(a => a.text === text)) return;
  inc.actions.push({ ts: now, text, kind, target });
  if (kind !== 'close' && responseComplete(inc)) { inc.status = 'Terkendali'; inc.actions.push({ ts: now, text: 'Seluruh langkah penahanan selesai — status otomatis menjadi TERKENDALI.' }); }
  renderAll(true);
}
function respOptions(inc) {
  const o = [];
  const srcs = new Set(); inc.alerts.forEach(a => { const s = a.ev.src; if (s && s !== 'INET' && ['workstation', 'camera', 'nvr'].includes(ASSET_BY_ID[s]?.type)) srcs.add(s);
    if (a.rule === 'RANSOMWARE' || a.rule === 'DDOS_OUT') srcs.add(a.ev.src); });
  srcs.forEach(s => o.push({ kind: 'iso', target: s, label: `Isolasi ${s}`, cls: 'warn' }));
  const ips = new Set(inc.alerts.flatMap(a => [a.ev.srcIp, a.ev.dstIp]).filter(Boolean)); ips.forEach(ip => o.push({ kind: 'blk', target: ip, label: `Blokir IP ${ip}`, cls: 'warn' }));
  const users = new Set(inc.alerts.filter(a => a.rule === 'BF_SUCCESS').map(a => a.ev.user)); users.forEach(u => o.push({ kind: 'cred', target: u, label: `Reset kredensial ${u}`, cls: '' }));
  if (inc.alerts.some(a => a.rule === 'MODBUS_WRITE')) o.push({ kind: 'plc', target: 'PLC-GENSET', label: 'Kunci PLC (RUN-LOCK)', cls: 'crit' });
  return o;
}
function responseComplete(inc) {
  const opts = respOptions(inc); return opts.length > 0 && opts.every(o => inc.actions.some(a => a.kind === o.kind && a.target === o.target));
}
function autoRespond(a) {
  const inc = eng.incidents.find(i => i.id === a.incident); if (!inc) return;
  respOptions(inc).forEach(o => { if (!inc.actions.some(x => x.kind === o.kind && x.target === o.target)) { act(inc, o.kind, o.target); inc.actions[inc.actions.length - 1].text += ' [OTOMATIS · SOAR]'; } });
  toast(`🛡️ <b>SOAR</b>: respons otomatis dijalankan untuk ${inc.id}`);
}

/* ---------- render ---------- */
function renderClock() { $('#clock').textContent = wib(simT, false) + ' WIB · sim'; }
function renderAll(force) {
  renderKpi(); renderNodes(); renderIncList(); renderIncDetail(); renderMatrix(); renderAssets(); renderReportSel(); renderScen();
}
const riskCol = r => r >= 70 ? 'var(--crit)' : r >= 45 ? 'var(--high)' : r >= 30 ? 'var(--med)' : 'var(--ok)';
function spark(id, arr, color, fixedMax) {
  const c = $(id); if (!c) return; const x = c.getContext('2d'), W = c.width, H = c.height; x.clearRect(0, 0, W, H);
  if (arr.length < 2) return; const mx = fixedMax || Math.max(1, ...arr) * 1.15;
  const pts = arr.map((v, i) => [i * W / (arr.length - 1), H - 2 - (v / mx) * (H - 6)]);
  const g = x.createLinearGradient(0, 0, 0, H); g.addColorStop(0, color + '55'); g.addColorStop(1, color + '00');
  x.beginPath(); x.moveTo(0, H); pts.forEach(p => x.lineTo(p[0], p[1])); x.lineTo(W, H); x.fillStyle = g; x.fill();
  x.beginPath(); pts.forEach((p, i) => i ? x.lineTo(p[0], p[1]) : x.moveTo(p[0], p[1])); x.strokeStyle = color; x.lineWidth = 1.6; x.stroke();
  const l = pts[pts.length - 1]; x.beginPath(); x.arc(l[0] - 2, l[1], 2.5, 0, 7); x.fillStyle = color; x.fill();
}
function renderKpi() {
  const p = eng.posture(); $('#kPosture').textContent = p;
  $('#kPostureTxt').textContent = p >= 80 ? 'SIAGA NORMAL' : p >= 60 ? 'WASPADA' : p >= 40 ? 'SIAGA II — ancaman aktif' : 'SIAGA I — serangan kritis';
  const col = p >= 80 ? 'var(--ok)' : p >= 60 ? 'var(--med)' : p >= 40 ? 'var(--high)' : 'var(--crit)';
  const hex = p >= 80 ? '#35d07f' : p >= 60 ? '#f0b429' : p >= 40 ? '#ff7a45' : '#ff3b5c';
  $('#kPosture').style.color = col;
  $('#threat').style.setProperty('--tc', col); $('#threatTxt').textContent = p >= 80 ? 'SIAGA NORMAL' : p >= 60 ? 'WASPADA' : p >= 40 ? 'SIAGA II' : 'SIAGA I';
  const C = 2 * Math.PI * 30;
  $('#gauge').innerHTML = `<svg viewBox="0 0 74 74"><defs><filter id="gl"><feGaussianBlur stdDeviation="2.2"/></filter></defs><circle cx="37" cy="37" r="30" fill="none" stroke="#1c2920" stroke-width="7"/>
    <circle cx="37" cy="37" r="30" fill="none" stroke="${col}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${C * p / 100} ${C}" transform="rotate(-90 37 37)" filter="url(#gl)" opacity=".6"/>
    <circle cx="37" cy="37" r="30" fill="none" stroke="${col}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${C * p / 100} ${C}" transform="rotate(-90 37 37)"/>
    <text x="37" y="41" text-anchor="middle" font-size="13" font-weight="700" fill="${col}" font-family="Bahnschrift,Segoe UI">${p}%</text></svg>`;
  const real = ASSETS.filter(a => a.id !== 'INET');
  $('#kAssets').textContent = real.length; $('#kIt').textContent = real.filter(a => a.zone !== 'ot').length; $('#kOt').textContent = real.filter(a => a.zone === 'ot').length;
  $('#kZones').innerHTML = ['dmz', 'it', 'ot'].map(z => { const r = Math.max(...real.filter(a => a.zone === z).map(a => eng.assetRisk(a.id)));
    return `<i title="${ZONES[z].name}: risiko maks ${r}" style="background:${riskCol(r)}"></i>`; }).join('');
  const span = Math.max(1, Math.min(60, simT));
  const epm = Math.round(eng.events.filter(e => e.ts > simT - span).length * 60 / span);
  $('#kEpm').textContent = epm;
  const alRate = eng.alerts.filter(a => a.ts > simT - 20).length;
  hist.epm.push(epm); hist.post.push(p); hist.al.push(alRate);
  for (const k in hist) if (hist[k].length > 90) hist[k].shift();
  spark('#spEpm', hist.epm, '#4aa3ff'); spark('#spPost', hist.post, hex, 100); spark('#spAl', hist.al, '#ff3b5c');
  $('#kIso').textContent = `${eng.isolated.size} host diisolasi${eng.plcLocked ? ' · PLC terkunci' : ''}`;
  const act = eng.incidents.filter(i => i.status === 'Aktif'); $('#kInc').textContent = act.length;
  $('#kInc').style.color = act.length ? 'var(--crit)' : 'var(--ok)';
  $('#kIncS').textContent = act.length ? `${act.filter(i => i.sev >= 4).length} kritis · ${act.filter(i => i.ot).length} melibatkan OT` : 'aman';
  $('#kBlk').textContent = blockedCount; $('#incBadge').textContent = act.length; $('#incBadge').style.display = act.length ? '' : 'none';
  $('#alertCount').textContent = eng.alerts.length + ' peringatan';
}
/* --- topologi berlapis: zona & kabel (statis), node (per render), aliran paket (per frame) --- */
function renderTopoStatic() {
  let z = `<defs><filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <radialGradient id="nodeBg"><stop offset="0" stop-color="#1b2a20"/><stop offset="1" stop-color="#0a110c"/></radialGradient></defs>`;
  for (const k in ZONES) { const Z = ZONES[k];
    z += `<rect class="zone-r" x="${Z.x}" y="${Z.y}" width="${Z.w}" height="${Z.h}" rx="12" fill="${Z.color}"/>
      <rect class="zone-h" x="${Z.x + 1}" y="${Z.y + 1}" width="${Z.w - 2}" height="24" rx="11" fill="rgba(255,255,255,.035)"/>
      <text class="zone-t" x="${Z.x + 12}" y="${Z.y + 17}">${Z.name}</text>`; }
  const L = (a, b, c = '') => z += `<line class="link ${c}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`;
  const A = ASSET_BY_ID; L(A['INET'], A['FW-01'], 'trunk'); L(A['SRV-MAIL'], A['FW-01']); L(A['FW-01'], HUBS.it, 'trunk'); L(HUBS.it, HUBS.ot, 'fw');
  ASSETS.forEach(a => { if (a.zone === 'it') L(a, HUBS.it); if (a.zone === 'ot') L(a, HUBS.ot); });
  for (const k in HUBS) { const h = HUBS[k]; z += `<g class="hub"><rect x="${h.x - 17}" y="${h.y - 8}" width="34" height="16" rx="4"/><text x="${h.x}" y="${h.y + 0.5}">${h.id}</text></g>`; }
  z += `<text x="${(HUBS.it.x + HUBS.ot.x) / 2}" y="${HUBS.it.y - 8}" text-anchor="middle" font-size="8" fill="#c98a4a" font-family="Cascadia Mono,Consolas">FW IT/OT</text>`;
  $('#topo').innerHTML = z + '<g id="tFlow"></g><g id="tNode"></g>';
}
function renderNodes() {
  const g = $('#tNode'); if (!g) return; let h = '';
  const incAssets = new Set(eng.incidents.filter(i => i.status === 'Aktif').flatMap(i => [...i.assets]));
  for (const a of ASSETS) {
    const r = eng.assetRisk(a.id); const col = a.id === 'INET' ? '#4a6a8a' : riskCol(r); const iso = eng.isolated.has(a.id);
    const C = 2 * Math.PI * 24;
    h += `<g class="node ${iso ? 'iso' : ''}" data-id="${a.id}">${incAssets.has(a.id) && !iso ? `<circle class="ring" cx="${a.x}" cy="${a.y}" r="21"/>` : ''}
      ${a.id !== 'INET' ? `<circle class="rkb" cx="${a.x}" cy="${a.y}" r="24"/><circle class="rk" cx="${a.x}" cy="${a.y}" r="24" stroke="${col}" stroke-dasharray="${C * Math.max(4, r) / 100} ${C}"/>` : ''}
      <circle class="c" cx="${a.x}" cy="${a.y}" r="19" fill="url(#nodeBg)" stroke="${col}" ${r >= 70 && !iso ? 'filter="url(#glow)"' : ''}/>
      <text class="ic" x="${a.x}" y="${a.y + 1}">${iso ? '🔒' : ICON[a.type]}</text>
      <text class="lb" x="${a.x}" y="${a.y + 37}">${a.id}</text>${a.id !== 'INET' ? `<text class="ip" x="${a.x}" y="${a.y + 47}">${a.ip}</text>` : ''}
      <title>${a.name} · ${a.ip} · risiko ${r}</title></g>`;
  }
  g.innerHTML = h;
}
function frame() {
  const g = $('#tFlow');
  if (g && $('#view-dash').classList.contains('active')) {
    const fr = Math.min(1, Math.max(0, (performance.now() - lastTickPerf) / 250));
    const now = prevSimT + fr * (simT - prevSimT); let h = '';
    for (const f of flows) {
      const e = f.e; if (e.ts > now) continue;
      const a = ASSET_BY_ID[e.src], b = ASSET_BY_ID[e.dst]; if (!a || !b) continue;
      const cls = e.blocked ? 'blk' : e.scen ? 'bad' : 'ok';
      const cx = (a.x + b.x) / 2, cy = (a.y + b.y) / 2 - 28;
      h += `<path class="flow ${cls}" d="M${a.x},${a.y} Q${cx},${cy} ${b.x},${b.y}"/>`;
      let p = (now - e.ts) / (0.7 * S.speed); if (e.blocked) p = Math.min(p, 0.5);
      if (p <= 1) {
        const q = 1 - p, x = q * q * a.x + 2 * q * p * cx + p * p * b.x, y = q * q * a.y + 2 * q * p * cy + p * p * b.y;
        h += e.blocked && p >= 0.5 ? `<path class="xmark" d="M${x - 5},${y - 5}L${x + 5},${y + 5}M${x + 5},${y - 5}L${x - 5},${y + 5}"/>`
          : `<circle class="pkt ${cls}" cx="${x}" cy="${y}" r="${cls === 'bad' ? 3.6 : 2.4}" ${cls === 'bad' ? 'filter="url(#glow)"' : ''}/>`;
      }
    }
    g.innerHTML = h;
  }
  requestAnimationFrame(frame);
}
function renderScen() {
  $('#scen').innerHTML = SCENARIOS.map(s => { const on = running.has(s.id);
    const pr = on && scenTotal[s.id] ? 100 * (1 - queue.filter(e => e.scen === s.id).length / scenTotal[s.id]) : 0;
    return `<div class="sc ${on ? 'running' : ''}"><div class="h"><span class="ic">${s.icon}</span>${esc(s.name)}<span class="tag ${s.dom === 'OT' ? 'ot' : ''}">${s.dom}</span></div>
    <p>${esc(s.desc)}</p><button class="btn small" data-scen="${s.id}" ${on ? 'disabled' : ''}>${on ? `⏳ Berjalan… ${Math.round(pr)}%` : '▶ Luncurkan'}</button>${on ? `<i class="prog" style="width:${pr}%"></i>` : ''}</div>`; }).join('');
}
function renderIncList() {
  const L = eng.incidents.slice().reverse();
  $('#incList').innerHTML = L.length ? L.map(i => `<div class="inc ${selInc === i.id ? 'sel' : ''}" data-inc="${i.id}"><div class="m" style="display:flex;gap:6px;align-items:center">
    <span class="sev s${i.sev}">${SEV_LABEL[i.sev]}</span><span class="st ${i.status}">${i.status.toUpperCase()}</span>${i.ot ? '<span class="tt ics">OT</span>' : ''}<span class="time" style="margin-left:auto">${i.id}</span></div>
    <div class="t">${esc(i.title)}</div><div class="time">${wib(i.first)} · ${i.alerts.length} peringatan · skor ${i.score}</div></div>`).join('') : '<div class="empty">Belum ada insiden.</div>';
}
function renderIncDetail() {
  const inc = eng.incidents.find(i => i.id === selInc);
  if (!inc) { if (!eng.incidents.length) $('#incDetail').innerHTML = '<div class="empty">Pilih insiden untuk melihat rantai serangan, teknik ATT&CK, dan opsi respons.</div>'; return; }
  const opts = respOptions(inc);
  $('#incDetail').innerHTML = `<div class="card-h"><h2>${inc.id} · ${esc(inc.title)}</h2><span class="st ${inc.status}">${inc.status.toUpperCase()}</span></div>
  <div class="dgrid"><div>
    <div class="muted small">Rantai serangan (MITRE ATT&CK kill chain)</div>
    <div class="kc">${TACTIC_ORDER.map(t => `<div class="${inc.tactics.includes(t) ? 'on' : ''}">${TACTIC_ID[t]}</div>`).join('')}</div>
    <div class="muted small" style="margin:10px 0 6px">Kronologi peringatan terkorelasi</div>
    <div class="tl">${inc.alerts.map(a => `<div class="it v${SEV[a.sev]}"><span class="time">${wib(a.ts)}</span> <span class="sev s${SEV[a.sev]}">${SEV_LABEL[SEV[a.sev]]}</span> <b>${esc(a.title)}</b><div class="small muted">${esc(a.detail)}</div></div>`).join('')}</div>
  </div><div class="side">
    <div class="muted small">Skor risiko insiden</div><div class="score" style="color:${inc.sev >= 4 ? 'var(--crit)' : inc.sev >= 3 ? 'var(--high)' : 'var(--med)'}">${inc.score}<span class="muted" style="font-size:14px">/100</span></div>
    <div class="muted small" style="margin-top:8px">Aset terlibat</div><div class="m" style="display:flex;gap:6px;flex-wrap:wrap;margin:4px 0">${[...inc.assets].map(x => `<span class="tt ${ASSET_BY_ID[x]?.zone === 'ot' ? 'ics' : ''}">${x}${eng.isolated.has(x) ? ' 🔒' : ''}</span>`).join('')}</div>
    <div class="muted small" style="margin-top:8px">Teknik terdeteksi</div><div style="font-size:12.5px">${[...inc.techs].sort().map(t => `<div><span class="tt ${MITRE[t].dom === 'ICS' ? 'ics' : ''}">${t}</span> ${esc(MITRE[t].name)}</div>`).join('')}</div>
    <div class="muted small" style="margin-top:12px">Playbook respons</div>
    <div class="actions">${opts.map(o => { const done = inc.actions.some(a => a.kind === o.kind && a.target === o.target);
      return `<button class="btn small ${o.cls}" data-act="${o.kind}" data-target="${esc(o.target)}" ${done ? 'disabled' : ''}>${done ? '✔ ' : ''}${esc(o.label)}</button>`; }).join('')}
      <button class="btn small ghost" data-act="close" ${inc.status !== 'Aktif' ? 'disabled' : ''}>Tandai terkendali</button>
      <button class="btn small" data-goreport="${inc.id}">📄 Buat LAPSUS</button></div>
    ${inc.actions.map(a => `<div class="done">✔ ${wib(a.ts)} ${esc(a.text)}</div>`).join('')}
  </div></div>`;
}
function renderMatrix() {
  const cnt = {}; eng.alerts.forEach(a => a.techs.forEach(t => cnt[t] = (cnt[t] || 0) + 1));
  $('#matrix').innerHTML = TACTIC_ORDER.map(tac => `<div class="mcol"><h4>${TACTIC_ID[tac]}<br>(${tac})</h4>${Object.entries(MITRE).filter(([, m]) => m.tactic === tac)
    .map(([id, m]) => `<div class="mcell ${m.dom === 'ICS' ? 'ics' : ''} ${cnt[id] ? 'hit' : ''}">${cnt[id] ? `<span class="n">${cnt[id]}</span>` : ''}<b>${id}</b>${esc(m.name)}</div>`).join('')}</div>`).join('');
}
function renderAssets() {
  const rows = ASSETS.filter(a => a.id !== 'INET').map(a => ({ a, r: eng.assetRisk(a.id) })).sort((x, y) => y.r - x.r);
  $('#assetTbl').innerHTML = `<tr><th>Aset</th><th>Nama</th><th>IP</th><th>Zona</th><th>Sistem</th><th>Kekritisan</th><th>Kerentanan</th><th>Peringatan</th><th>Risiko</th><th>Status</th></tr>` +
    rows.map(({ a, r }) => { const col = r >= 70 ? 'var(--crit)' : r >= 45 ? 'var(--high)' : r >= 30 ? 'var(--med)' : 'var(--ok)';
      const n = eng.alerts.filter(x => x.assets.includes(a.id)).length;
      return `<tr><td>${ICON[a.type]} <b>${a.id}</b></td><td>${esc(a.name)}</td><td class="mono">${a.ip}</td><td>${a.zone === 'ot' ? '<span class="tt ics">OT/IoT</span>' : a.zone === 'dmz' ? 'DMZ' : 'IT'}</td><td class="small">${esc(a.os)}</td>
      <td>${'★'.repeat(a.crit)}<span class="muted">${'★'.repeat(5 - a.crit)}</span></td><td class="small">${a.vulns.map(esc).join(', ') || '<span class="muted">-</span>'}</td><td>${n}</td>
      <td><div style="display:flex;gap:6px;align-items:center"><div class="bar"><i style="width:${r}%;background:${col}"></i></div><b style="color:${col}">${r}</b></div></td>
      <td>${eng.isolated.has(a.id) ? '<span class="st Aktif">DIISOLASI</span>' : '<span class="st Terkendali">ONLINE</span>'}</td></tr>`; }).join('');
}
let repCur = null;
function renderReportSel() {
  const sel = $('#repSel'); const ids = eng.incidents.map(i => i.id);
  const cur = sel.value; const html = ids.length ? ids.map(id => { const i = eng.incidents.find(x => x.id === id); return `<option value="${id}">${id} — ${esc(i.title)}</option>`; }).join('') : '<option value="">(belum ada insiden)</option>';
  if (sel.dataset.h !== html) { sel.innerHTML = html; sel.dataset.h = html; if (ids.includes(cur)) sel.value = cur; }
  if ($('#view-report').classList.contains('active')) renderReport();
}
function renderReport() {
  const inc = eng.incidents.find(i => i.id === $('#repSel').value);
  if (!inc) return;
  const txt = buildReport(inc, eng); if (txt !== repCur) { $('#report').textContent = txt; repCur = txt; }
}
function download(name, text, type = 'text/plain') {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------- analisis log ---------- */
function analyzeLogs() {
  const evs = parseLogs($('#logIn').value);
  const e2 = new DetectionEngine({});
  evs.forEach(e => e2.ingest(e));
  $('#logStat').textContent = `${evs.length} baris dikenali · ${e2.alerts.length} temuan · ${e2.incidents.length} insiden`;
  $('#logOut').innerHTML = e2.alerts.length ? e2.alerts.slice().reverse().map(alertHtml).join('') +
    `<button class="btn" id="btnLogRep">📄 Unduh LAPSUS dari hasil analisis</button>` : '<div class="empty">Tidak ditemukan ancaman pada log ini.</div>';
  const b = $('#btnLogRep'); if (b) b.onclick = () => download('LAPSUS-analisis-log.txt', e2.incidents.map(i => buildReport(i, e2)).join('\n\n' + '='.repeat(70) + '\n\n'));
}

/* ---------- event binding ---------- */
document.addEventListener('click', ev => {
  const t = ev.target.closest('button,[data-inc]'); if (!t) return;
  if (t.dataset.view) { document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('active', b === t)); document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + t.dataset.view)); if (t.dataset.view === 'report') renderReport(); return; }
  if (t.dataset.scen) return runScenario(t.dataset.scen);
  if (t.dataset.inc) { selInc = t.dataset.inc; renderIncList(); renderIncDetail(); return; }
  if (t.dataset.act) { const inc = eng.incidents.find(i => i.id === selInc); if (inc) act(inc, t.dataset.act, t.dataset.target); return; }
  if (t.dataset.goreport) { $('#repSel').value = t.dataset.goreport; document.querySelector('[data-view=report]').click(); return; }
});
$('#speed').onchange = e => S.speed = +e.target.value;
$('#btnReset').onclick = () => reset();
$('#btnAll').onclick = () => { SCENARIOS.forEach((s, i) => setTimeout(() => runScenario(s.id), i * 9000 / S.speed)); };
$('#repSel').onchange = renderReport;
$('#btnTxt').onclick = () => { const v = $('#repSel').value; if (v) download(`LAPSUS-${v}.txt`, $('#report').textContent); };
$('#btnPrint').onclick = () => window.print();
$('#btnStix').onclick = () => { const inc = eng.incidents.find(i => i.id === $('#repSel').value); if (inc) download(`IoC-${inc.id}.stix.json`, buildStix(inc), 'application/json'); };
$('#btnSample').onclick = () => { $('#logIn').value = SAMPLE_LOG; };
$('#btnAnalyze').onclick = analyzeLogs;
$('#logFile').onchange = e => { const f = e.target.files[0]; if (f) f.text().then(t => { $('#logIn').value = t; analyzeLogs(); }); };

/* ---------- boot ---------- */
reset();
requestAnimationFrame(frame);
(function boot() {
  const step = (t, w) => { $('#spStep').textContent = t; $('#spBar').style.width = w + '%'; };
  const later = (ms, f) => setTimeout(f, ms);
  step('Memuat inventaris 18 aset IT & OT/IoT…', 18);
  later(300, () => {
    step('Melatih baseline AI (Isolation Forest) per aset…', 45);
    later(60, () => {
      const t0 = performance.now(); const { model, n } = trainBaseline(); MODEL = model; eng.model = model;
      const ms = Math.round(performance.now() - t0);
      $('#chipModel').textContent = `AI: Isolation Forest aktif · baseline ${n} jendela · ${ms} ms`; $('#chipModel').classList.add('ok');
      step(`Baseline terbentuk: ${n} jendela perilaku (${ms} ms) · memuat 16 aturan deteksi…`, 75);
      later(350, () => { step('Memuat basis pengetahuan MITRE ATT&CK Enterprise + ICS…', 92);
        later(300, () => { step('Siap · mode air-gapped · 0 byte keluar', 100);
          later(350, () => { $('#splash').classList.add('hide'); setInterval(tick, 250);
            const q = new URLSearchParams(location.search); if (q.get('auto')) setTimeout(() => $('#btnAll').click(), 1200); }); }); });
    });
  });
})();
