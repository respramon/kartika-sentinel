/* KARTIKA-SENTINEL — antarmuka AI generatif: pengaturan penyedia, analisis insiden, LAPSUS, analisis log, chat */
'use strict';
const aiIncOut = {};      // { incId: {busy, html, err} }
const aiReport = {};      // { incId: {text, on} }
let aiChatHist = [], aiLogCtx = '', aiModelCache = [];

/* ---------- status di header ---------- */
function aiRenderStatus() {
  const chip = $('#chipLLM'), gap = $('#chipGap');
  if (!AI.cfg.enabled) { chip.textContent = '⚙ AI generatif: nonaktif'; chip.className = 'chip btnchip'; gap.className = 'chip ok'; gap.textContent = '● MODE AIR-GAPPED · 0 byte keluar'; return; }
  const loc = AI.locality();
  chip.textContent = `⚙ LLM: ${AI.label()}`; chip.className = 'chip btnchip ' + (AI.ready() ? (loc === 'cloud' ? 'warn' : 'ok') : 'bad');
  if (loc === 'local') { gap.className = 'chip ok'; gap.textContent = '● AIR-GAPPED · LLM lokal'; }
  else if (loc === 'router') { gap.className = 'chip warn'; gap.textContent = '◐ LLM via router — cek tujuan akhir'; }
  else { gap.className = 'chip warn'; gap.textContent = `▲ LLM cloud aktif · data dikirim ke ${AI.prov().name}`; }
}
function aiNeed() {
  if (AI.ready()) return true;
  toast('🧠 <b>AI generatif belum dikonfigurasi.</b> Pilih penyedia AI terlebih dahulu.'); aiOpen(); return false;
}

/* ---------- modal pengaturan ---------- */
function aiOpen() { aiFillForm(); $('#aiModal').classList.add('open'); }
function aiClose() { $('#aiModal').classList.remove('open'); }
function aiFillForm() {
  const sel = $('#aiProv');
  if (!sel.options.length) sel.innerHTML = Object.entries(AI_CATS).map(([c, m]) => `<optgroup label="${m.label}">${AI_PROVIDERS.filter(p => p.cat === c).map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('')}</optgroup>`).join('');
  $('#aiEnabled').checked = AI.cfg.enabled; sel.value = AI.cfg.provider;
  $('#aiKey').value = AI.key; $('#aiModel').value = AI.cfg.model; $('#aiMaxT').value = AI.cfg.maxTokens; $('#aiTemp').value = AI.cfg.temperature;
  $('#aiRedact').checked = AI.cfg.redact; $('#aiRemember').checked = AI.cfg.remember; $('#aiHeaders').value = AI.cfg.headers;
  $('#aiBase').value = AI.cfg.base || AI.prov().base; aiModelCache = [];
  aiProvChanged(false);
}
function aiProvChanged(resetBase = true) {
  const p = AI_BY_ID[$('#aiProv').value];
  if (resetBase) { $('#aiBase').value = p.base; $('#aiModel').value = p.models[0] || ''; aiModelCache = []; $('#aiTest').className = 'testout'; $('#aiTest').textContent = ''; }
  $('#aiCat').textContent = AI_CATS[p.cat].badge; $('#aiCat').className = 'cat c-' + p.cat;
  $('#aiHelp').textContent = p.help || '';
  $('#aiKeyRow').style.display = p.key || p.keyOpt ? '' : 'none';
  $('#aiKeyLbl').textContent = p.key ? 'API key (wajib)' : 'API key (opsional)';
  $('#aiTempRow').style.display = p.noTemp ? 'none' : '';
  $('#aiModelRow').style.display = p.style === 'azure' ? 'none' : '';
  $('#aiExtra').innerHTML = (p.extra || []).map(f => `<label class="fld"><span>${esc(f.label)}</span><input data-extra="${f.k}" placeholder="${esc(f.ph || '')}" value="${esc((AI.cfg.provider === p.id && AI.cfg.extra[f.k]) || f.def || '')}"></label>`).join('');
  $('#aiBtnList').style.display = p.noList || p.style === 'azure' ? 'none' : '';
  aiRenderModelList(); aiLocNote();
}
function aiRenderModelList() {
  const p = AI_BY_ID[$('#aiProv').value];
  const all = [...new Set([...(aiModelCache.length ? aiModelCache : []), ...p.models])];
  $('#aiModelList').innerHTML = all.map(m => `<option value="${esc(m)}">`).join('');
  $('#aiChips').innerHTML = (aiModelCache.length ? aiModelCache.slice(0, 40) : p.models).map(m => `<button type="button" class="mchip" data-model="${esc(m)}">${esc(m)}</button>`).join('') ||
    '<span class="muted small">Belum ada daftar — klik "Ambil daftar model" atau ketik nama model.</span>';
}
function aiFormToCfg() {
  const p = AI_BY_ID[$('#aiProv').value]; const extra = {};
  document.querySelectorAll('#aiExtra [data-extra]').forEach(i => extra[i.dataset.extra] = i.value.trim());
  Object.assign(AI.cfg, { enabled: $('#aiEnabled').checked, provider: p.id, base: $('#aiBase').value.trim(), model: $('#aiModel').value.trim(),
    maxTokens: +$('#aiMaxT').value || 2048, temperature: $('#aiTemp').value.trim(), redact: $('#aiRedact').checked, remember: $('#aiRemember').checked,
    headers: $('#aiHeaders').value, extra });
  AI.key = $('#aiKey').value.trim();
}
function aiLocNote() {
  const saved = { ...AI.cfg, extra: { ...AI.cfg.extra } }, k = AI.key; aiFormToCfg();
  const loc = AI.locality();
  $('#aiLoc').className = 'locnote ' + loc;
  $('#aiLoc').innerHTML = loc === 'local' ? '🟢 <b>Lokal</b> — data insiden tetap di jaringan/perangkat satuan. Direkomendasikan untuk operasi nyata.'
    : loc === 'router' ? '🟡 <b>Router/gateway</b> — router berjalan lokal, tetapi dapat meneruskan data ke penyedia cloud sesuai konfigurasinya.'
      : `🔴 <b>Cloud</b> — ringkasan insiden akan dikirim ke server ${esc(AI_BY_ID[AI.cfg.provider].name)}. Gunakan hanya untuk latihan/data tidak rahasia; aktifkan penyamaran IP.`;
  Object.assign(AI.cfg, saved); AI.key = k;
}
async function aiFetchModels() {
  const prev = { ...AI.cfg, extra: { ...AI.cfg.extra } }, pk = AI.key; aiFormToCfg(); AI.cfg.enabled = true;
  const out = $('#aiTest'); out.className = 'testout'; out.textContent = 'Mengambil daftar model…';
  try { aiModelCache = await aiListModels(); out.className = 'testout ok'; out.textContent = `✔ ${aiModelCache.length} model ditemukan. Klik salah satu untuk memilih.`;
    if (!$('#aiModel').value && aiModelCache[0]) $('#aiModel').value = aiModelCache[0]; aiRenderModelList(); }
  catch (e) { out.className = 'testout bad'; out.textContent = '✖ ' + e.message; }
  finally { Object.assign(AI.cfg, prev); AI.key = pk; }
}
async function aiTestConn() {
  const prev = { ...AI.cfg, extra: { ...AI.cfg.extra } }, pk = AI.key; aiFormToCfg(); AI.cfg.enabled = true;
  const out = $('#aiTest'); out.className = 'testout'; out.textContent = `Menguji ${AI.label()}…`; const t0 = performance.now();
  try {
    if (!AI.ready()) throw new Error('Lengkapi base URL, model/deployment, dan API key (jika wajib).');
    const r = await aiChat([{ role: 'user', content: 'Balas tepat dengan kalimat: "SENTINEL-AI siap."' }], 'Anda asisten uji koneksi. Jawab sangat singkat.', { maxTokens: 64 });
    out.className = 'testout ok'; out.textContent = `✔ Terhubung (${Math.round(performance.now() - t0)} ms). Jawaban model: "${r.slice(0, 120)}"`;
  } catch (e) { out.className = 'testout bad'; out.textContent = '✖ ' + e.message; }
  finally { Object.assign(AI.cfg, prev); AI.key = pk; }
}
function aiSave() {
  aiFormToCfg();
  if (AI.cfg.headers.trim()) { try { JSON.parse(AI.cfg.headers); } catch (e) { $('#aiTest').className = 'testout bad'; $('#aiTest').textContent = '✖ Header tambahan harus JSON, contoh {"X-Org":"satuan"}'; return; } }
  AI.save(); aiRenderStatus(); aiClose(); renderAll();
  toast(AI.cfg.enabled ? `🧠 AI generatif aktif: <b>${esc(AI.label())}</b>` : '🧠 AI generatif dinonaktifkan — mode air-gapped penuh.');
}
function aiReset() {
  AI.clear(); AI.key = ''; Object.assign(AI.cfg, { enabled: false, provider: 'ollama', base: '', model: '', maxTokens: 2048, temperature: '', redact: true, remember: false, headers: '', extra: {} });
  aiFillForm(); aiRenderStatus(); $('#aiTest').className = 'testout'; $('#aiTest').textContent = 'Konfigurasi & API key dihapus dari peramban ini.';
}

/* ---------- fitur: analisis insiden ---------- */
function aiIncBlock(inc) {
  const o = aiIncOut[inc.id];
  const btn = `<button class="btn small ai" data-ai-inc="${inc.id}" ${o?.busy ? 'disabled' : ''}>${o?.busy ? '⏳ AI menganalisis…' : o?.html ? '🧠 Analisis ulang dengan AI' : '🧠 Analisis AI'}</button>`;
  const body = o?.err ? `<div class="aibox err">✖ ${esc(o.err)}</div>` : o?.html ? `<div class="aibox"><div class="aihead">🧠 Analisis AI · ${esc(o.by)}</div>${o.html}</div>` : '';
  return `<div class="aiwrap">${btn}${body}</div>`;
}
async function aiAnalyzeInc(id) {
  if (!aiNeed()) return; const inc = eng.incidents.find(i => i.id === id); if (!inc) return;
  aiIncOut[id] = { busy: true }; renderIncDetail();
  try { const r = await aiChat([{ role: 'user', content: AI_TASKS.analyze(aiIncidentContext(inc, eng)) }], AI_SYSTEM); aiIncOut[id] = { html: aiMd(r), by: AI.label() }; }
  catch (e) { aiIncOut[id] = { err: e.message }; }
  renderIncDetail();
}

/* ---------- fitur: LAPSUS ---------- */
async function aiImproveReport() {
  if (!aiNeed()) return; const id = $('#repSel').value; const inc = eng.incidents.find(i => i.id === id); if (!inc) return;
  const b = $('#btnAIRep'); b.disabled = true; b.textContent = '⏳ AI menyempurnakan…';
  try {
    const draft = aiRedact(buildReport(inc, eng));
    const r = await aiChat([{ role: 'user', content: AI_TASKS.report(aiIncidentContext(inc, eng), draft) }], AI_SYSTEM, { maxTokens: Math.max(3000, +AI.cfg.maxTokens) });
    aiReport[id] = { text: r.replace(/^```[a-z]*\n?|```$/g, '').trim() + `\n\n— Narasi disempurnakan oleh AI (${AI.label()}); wajib diverifikasi Perwira Siber. —`, on: true };
    repCur = null; renderReport(); toast('✨ LAPSUS disempurnakan oleh AI');
  } catch (e) { toast('✖ <b>AI gagal:</b> ' + esc(e.message)); }
  finally { b.disabled = false; b.textContent = '✨ Sempurnakan dengan AI'; aiRepButtons(); }
}
function aiRepButtons() {
  const id = $('#repSel').value; $('#btnTplRep').style.display = aiReport[id]?.on ? '' : 'none';
  $('#repStamp').textContent = aiReport[id]?.on ? 'DRAF · AI' : 'DRAF';
}

/* ---------- fitur: analisis log ---------- */
async function aiExplainLogs() {
  if (!aiNeed() || !aiLogCtx) return; const box = $('#aiLogOut'); box.innerHTML = '<div class="aibox">⏳ AI sedang menjelaskan temuan…</div>';
  try { const r = await aiChat([{ role: 'user', content: AI_TASKS.logs(aiRedact(aiLogCtx)) }], AI_SYSTEM); box.innerHTML = `<div class="aibox"><div class="aihead">🧠 Penjelasan AI · ${esc(AI.label())}</div>${aiMd(r)}</div>`; }
  catch (e) { box.innerHTML = `<div class="aibox err">✖ ${esc(e.message)}</div>`; }
}

/* ---------- fitur: chat Tanya SENTINEL ---------- */
function aiChatToggle() { $('#aiChat').classList.toggle('open'); if ($('#aiChat').classList.contains('open')) $('#aiQ').focus(); }
function aiChatRender() {
  $('#aiMsgs').innerHTML = aiChatHist.length ? aiChatHist.map(m => `<div class="msg ${m.role}">${m.role === 'user' ? esc(m.content) : aiMd(m.content)}</div>`).join('')
    : `<div class="muted small" style="padding:8px">Tanyakan apa saja tentang situasi siber satuan. Konteks insiden & aset terkini dilampirkan otomatis${AI.cfg.redact ? ' (IP internal disamarkan)' : ''}.</div>`;
  $('#aiMsgs').scrollTop = 1e9;
}
async function aiAsk(q) {
  q = (q || $('#aiQ').value).trim(); if (!q) return; if (!aiNeed()) return;
  $('#aiQ').value = ''; aiChatHist.push({ role: 'user', content: q }); aiChatHist.push({ role: 'assistant', content: '⏳ …', pending: true }); aiChatRender();
  try {
    const hist = aiChatHist.filter(m => !m.pending).slice(-10).map(m => ({ role: m.role, content: m.content }));
    const r = await aiChat(hist, AI_SYSTEM + '\n\nSITUASI TERKINI (otomatis dari KARTIKA-SENTINEL):\n' + aiSituationContext(eng));
    aiChatHist[aiChatHist.length - 1] = { role: 'assistant', content: r };
  } catch (e) { aiChatHist[aiChatHist.length - 1] = { role: 'assistant', content: '✖ ' + e.message }; }
  aiChatRender();
}

/* ---------- binding ---------- */
document.addEventListener('click', ev => {
  const t = ev.target.closest('[data-ai-inc],[data-model],#chipLLM,#aiX,#aiBtnTest,#aiBtnSave,#aiBtnReset,#aiBtnList,#btnAIRep,#btnTplRep,#aiFab,#aiChatX,#aiSend,[data-q],#btnAILog,#aiKeyShow');
  if (!t) { if (ev.target.id === 'aiModal') aiClose(); return; }
  if (t.dataset.aiInc) return aiAnalyzeInc(t.dataset.aiInc);
  if (t.dataset.model) { $('#aiModel').value = t.dataset.model; return; }
  if (t.dataset.q) return aiAsk(t.dataset.q);
  ({ chipLLM: aiOpen, aiX: aiClose, aiBtnTest: aiTestConn, aiBtnSave: aiSave, aiBtnReset: aiReset, aiBtnList: aiFetchModels, btnAIRep: aiImproveReport,
    btnTplRep: () => { const id = $('#repSel').value; if (aiReport[id]) aiReport[id].on = false; repCur = null; renderReport(); aiRepButtons(); },
    aiFab: aiChatToggle, aiChatX: aiChatToggle, aiSend: () => aiAsk(), btnAILog: aiExplainLogs,
    aiKeyShow: () => { const k = $('#aiKey'); k.type = k.type === 'password' ? 'text' : 'password'; } })[t.id]?.();
});
$('#aiProv').addEventListener('change', () => aiProvChanged(true));
['#aiBase', '#aiEnabled'].forEach(s => $(s).addEventListener('input', aiLocNote));
$('#aiQ').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); aiAsk(); } });
document.addEventListener('keydown', e => { if (e.key === 'Escape') aiClose(); });
aiRenderStatus(); aiChatRender();
