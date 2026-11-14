/* KARTIKA-SENTINEL — Konektor AI Generatif (LLM) multi-penyedia
 * Bawaan: NONAKTIF (mode air-gapped). Jika diaktifkan, pengguna memilih penyedia: cloud berbayar, gratis/free-tier,
 * router/gateway (OmniRoute, 9router, LiteLLM, OpenRouter), lokal (Ollama, LM Studio, llama.cpp, vLLM, LocalAI, Jan) atau kustom.
 * Tiga gaya API: OpenAI-compatible (/chat/completions), Anthropic Messages (/messages), Azure OpenAI (deployment).
 * Kunci API hanya disimpan di peramban pengguna (sessionStorage; localStorage bila "ingat" dicentang). */
'use strict';

const AI_CATS = {
  cloud: { label: 'Cloud berbayar', badge: 'BERBAYAR' },
  free: { label: 'Gratis / free tier', badge: 'GRATIS' },
  router: { label: 'Router / gateway', badge: 'ROUTER' },
  local: { label: 'Lokal (on-premise)', badge: 'LOKAL' },
  custom: { label: 'Kustom', badge: 'KUSTOM' },
};

// Daftar model preset hanya saran — gunakan "Ambil daftar model" untuk daftar terbaru dari penyedia.
const AI_PROVIDERS = [
  // ---- Cloud berbayar ----
  { id: 'openai', name: 'OpenAI', cat: 'cloud', style: 'openai', base: 'https://api.openai.com/v1', key: true, models: ['gpt-5', 'gpt-5-mini', 'gpt-5-nano', 'gpt-4.1', 'gpt-4.1-mini', 'gpt-4o-mini'], tokenParam: 'max_completion_tokens', noTemp: true, help: 'Buat API key di platform.openai.com → API keys.' },
  { id: 'anthropic', name: 'Anthropic Claude', cat: 'cloud', style: 'anthropic', base: 'https://api.anthropic.com/v1', key: true, models: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5', 'claude-fable-5-2'], noTemp: true, help: 'Buat API key di platform.claude.com → API Keys. Permintaan dikirim langsung dari peramban.' },
  { id: 'azure', name: 'Azure OpenAI', cat: 'cloud', style: 'azure', base: 'https://NAMA-RESOURCE.openai.azure.com', key: true, models: [], tokenParam: 'max_completion_tokens', extra: [{ k: 'deployment', label: 'Nama deployment', ph: 'gpt-4o-mini-sentinel' }, { k: 'apiVersion', label: 'API version', ph: '2024-10-21', def: '2024-10-21' }], help: 'Endpoint resource Azure + nama deployment model. Kunci dari Azure Portal → Keys and Endpoint.' },
  { id: 'mistral', name: 'Mistral AI', cat: 'cloud', style: 'openai', base: 'https://api.mistral.ai/v1', key: true, models: ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest', 'open-mistral-nemo'], help: 'API key dari console.mistral.ai (tersedia paket eksperimen gratis).' },
  { id: 'deepseek', name: 'DeepSeek', cat: 'cloud', style: 'openai', base: 'https://api.deepseek.com/v1', key: true, models: ['deepseek-chat', 'deepseek-reasoner'], help: 'API key dari platform.deepseek.com.' },
  { id: 'xai', name: 'xAI Grok', cat: 'cloud', style: 'openai', base: 'https://api.x.ai/v1', key: true, models: ['grok-4', 'grok-3-mini'], help: 'API key dari console.x.ai.' },
  { id: 'cohere', name: 'Cohere', cat: 'cloud', style: 'openai', base: 'https://api.cohere.ai/compatibility/v1', key: true, models: ['command-a-03-2025', 'command-r-plus', 'command-r'], help: 'Memakai endpoint kompatibilitas OpenAI milik Cohere (ada trial key gratis).' },
  { id: 'perplexity', name: 'Perplexity', cat: 'cloud', style: 'openai', base: 'https://api.perplexity.ai', key: true, models: ['sonar', 'sonar-pro', 'sonar-reasoning'], noList: true, help: 'API key dari perplexity.ai/settings/api.' },
  { id: 'together', name: 'Together AI', cat: 'cloud', style: 'openai', base: 'https://api.together.xyz/v1', key: true, models: ['meta-llama/Llama-3.3-70B-Instruct-Turbo', 'Qwen/Qwen2.5-72B-Instruct-Turbo', 'deepseek-ai/DeepSeek-V3'], help: 'API key dari api.together.ai.' },
  { id: 'fireworks', name: 'Fireworks AI', cat: 'cloud', style: 'openai', base: 'https://api.fireworks.ai/inference/v1', key: true, models: ['accounts/fireworks/models/llama-v3p3-70b-instruct', 'accounts/fireworks/models/deepseek-v3'], help: 'API key dari fireworks.ai.' },
  // ---- Gratis / free tier ----
  { id: 'gemini', name: 'Google Gemini (AI Studio)', cat: 'free', style: 'openai', base: 'https://generativelanguage.googleapis.com/v1beta/openai', key: true, models: ['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-2.5-pro'], help: 'API key gratis dari aistudio.google.com (kuota harian). Memakai endpoint kompatibel OpenAI.' },
  { id: 'groq', name: 'Groq', cat: 'free', style: 'openai', base: 'https://api.groq.com/openai/v1', key: true, models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b'], help: 'Free tier dengan batas laju; key dari console.groq.com. Sangat cepat.' },
  { id: 'cerebras', name: 'Cerebras', cat: 'free', style: 'openai', base: 'https://api.cerebras.ai/v1', key: true, models: ['llama-3.3-70b', 'gpt-oss-120b', 'qwen-3-32b'], help: 'Free tier; key dari cloud.cerebras.ai.' },
  { id: 'github', name: 'GitHub Models', cat: 'free', style: 'openai', base: 'https://models.github.ai/inference', key: true, models: ['openai/gpt-4.1-mini', 'openai/gpt-4.1', 'meta/Llama-3.3-70B-Instruct', 'deepseek/DeepSeek-V3-0324'], noList: true, help: 'Gratis dengan GitHub Personal Access Token (izin models:read).' },
  { id: 'hf', name: 'Hugging Face Inference', cat: 'free', style: 'openai', base: 'https://router.huggingface.co/v1', key: true, models: ['meta-llama/Llama-3.3-70B-Instruct', 'Qwen/Qwen2.5-72B-Instruct', 'deepseek-ai/DeepSeek-V3-0324'], help: 'Kredit gratis bulanan; token dari huggingface.co/settings/tokens.' },
  { id: 'sambanova', name: 'SambaNova Cloud', cat: 'free', style: 'openai', base: 'https://api.sambanova.ai/v1', key: true, models: ['Meta-Llama-3.3-70B-Instruct', 'DeepSeek-V3-0324'], help: 'Free tier; key dari cloud.sambanova.ai.' },
  { id: 'nvidia', name: 'NVIDIA NIM (build.nvidia.com)', cat: 'free', style: 'openai', base: 'https://integrate.api.nvidia.com/v1', key: true, models: ['meta/llama-3.3-70b-instruct', 'deepseek-ai/deepseek-r1', 'qwen/qwen2.5-coder-32b-instruct'], help: 'Kredit gratis untuk pengembang. Catatan: endpoint ini mungkin memblokir permintaan langsung dari peramban (CORS) — gunakan lewat router (LiteLLM/OmniRoute).' },
  { id: 'cloudflare', name: 'Cloudflare Workers AI', cat: 'free', style: 'openai', base: 'https://api.cloudflare.com/client/v4/accounts/{accountId}/ai/v1', key: true, models: ['@cf/meta/llama-3.3-70b-instruct-fp8-fast', '@cf/meta/llama-3.1-8b-instruct'], noList: true, extra: [{ k: 'accountId', label: 'Account ID', ph: '32 karakter heksadesimal' }], help: 'Kuota gratis harian. Token API dengan izin Workers AI. Mungkin perlu lewat router karena CORS.' },
  // ---- Router / gateway ----
  { id: 'openrouter', name: 'OpenRouter', cat: 'router', style: 'openai', base: 'https://openrouter.ai/api/v1', key: true, models: ['openrouter/auto', 'meta-llama/llama-3.3-70b-instruct:free', 'deepseek/deepseek-chat-v3-0324:free', 'anthropic/claude-sonnet-5-5', 'openai/gpt-5-mini'], headers: { 'X-Title': 'KARTIKA-SENTINEL' }, help: 'Satu key untuk ratusan model; model berakhiran ":free" gratis. Key dari openrouter.ai/keys.' },
  { id: 'omniroute', name: 'OmniRoute', cat: 'router', style: 'openai', base: 'http://localhost:20128/v1', key: false, keyOpt: true, models: [], help: 'Gateway AI open-source (self-hosted). Jalankan OmniRoute, buat API key di dasbornya, lalu klik "Ambil daftar model" (format model: penyedia/model).' },
  { id: '9router', name: '9router', cat: 'router', style: 'openai', base: 'http://localhost:20128/v1', key: false, keyOpt: true, models: [], help: 'Router AI lokal (npm i -g 9router, lalu jalankan "9router"). Endpoint bawaan http://localhost:20128/v1; key dibuat di dasbor 9router.' },
  { id: 'litellm', name: 'LiteLLM Proxy', cat: 'router', style: 'openai', base: 'http://localhost:4000/v1', key: false, keyOpt: true, models: [], help: 'Proxy LiteLLM (litellm --config config.yaml). Cocok untuk menyatukan banyak penyedia di jaringan satuan.' },
  // ---- Lokal ----
  { id: 'ollama', name: 'Ollama', cat: 'local', style: 'openai', base: 'http://localhost:11434/v1', key: false, models: ['llama3.1:8b', 'qwen2.5:7b', 'gemma3:4b', 'mistral:7b', 'deepseek-r1:8b'], help: 'Sepenuhnya lokal & gratis. Jalankan "ollama pull qwen2.5:7b". Jika halaman dibuka dari domain lain, set variabel OLLAMA_ORIGINS=* lalu restart Ollama.' },
  { id: 'lmstudio', name: 'LM Studio', cat: 'local', style: 'openai', base: 'http://localhost:1234/v1', key: false, models: [], help: 'Aktifkan "Local Server" di LM Studio dan nyalakan opsi CORS.' },
  { id: 'llamacpp', name: 'llama.cpp server', cat: 'local', style: 'openai', base: 'http://localhost:8080/v1', key: false, keyOpt: true, models: [], help: 'llama-server -m model.gguf --port 8080 (CORS aktif secara bawaan).' },
  { id: 'vllm', name: 'vLLM', cat: 'local', style: 'openai', base: 'http://localhost:8000/v1', key: false, keyOpt: true, models: [], help: 'vllm serve <model> --allowed-origins \'["*"]\' — cocok untuk server GPU satuan.' },
  { id: 'localai', name: 'LocalAI', cat: 'local', style: 'openai', base: 'http://localhost:8080/v1', key: false, keyOpt: true, models: [], help: 'Server LocalAI (docker run localai/localai).' },
  { id: 'jan', name: 'Jan', cat: 'local', style: 'openai', base: 'http://localhost:1337/v1', key: false, keyOpt: true, models: [], help: 'Aktifkan "Local API Server" di aplikasi Jan.' },
  // ---- Kustom ----
  { id: 'custom', name: 'Kustom (OpenAI-compatible)', cat: 'custom', style: 'openai', base: '', key: false, keyOpt: true, models: [], help: 'Endpoint apa pun yang kompatibel OpenAI (/chat/completions), misalnya server LLM internal satuan.' },
  { id: 'custom-anthropic', name: 'Kustom (Anthropic-compatible)', cat: 'custom', style: 'anthropic', base: '', key: false, keyOpt: true, models: [], help: 'Endpoint yang kompatibel dengan Anthropic Messages API (/messages).' },
];
const AI_BY_ID = Object.fromEntries(AI_PROVIDERS.map(p => [p.id, p]));

/* ---------------- konfigurasi ---------------- */
const AI = {
  cfg: { enabled: false, provider: 'ollama', base: '', model: '', maxTokens: 2048, temperature: '', redact: true, remember: false, headers: '', extra: {} },
  key: '',
  load() {
    try { const s = JSON.parse(localStorage.getItem('ks-ai') || 'null'); if (s) Object.assign(this.cfg, s); } catch (e) {}
    try { this.key = sessionStorage.getItem('ks-ai-key') || localStorage.getItem('ks-ai-key') || ''; } catch (e) {}
  },
  save() {
    try {
      localStorage.setItem('ks-ai', JSON.stringify(this.cfg));
      sessionStorage.setItem('ks-ai-key', this.key);
      if (this.cfg.remember) localStorage.setItem('ks-ai-key', this.key); else localStorage.removeItem('ks-ai-key');
    } catch (e) {}
  },
  clear() { try { localStorage.removeItem('ks-ai'); localStorage.removeItem('ks-ai-key'); sessionStorage.removeItem('ks-ai-key'); } catch (e) {} },
  prov() { return AI_BY_ID[this.cfg.provider] || AI_BY_ID.custom; },
  baseUrl() {
    let b = (this.cfg.base || this.prov().base || '').trim().replace(/\/+$/, '');
    return b.replace('{accountId}', encodeURIComponent(this.cfg.extra.accountId || ''));
  },
  ready() { return this.cfg.enabled && this.baseUrl() && (this.cfg.model || this.prov().style === 'azure') && (!this.prov().key || this.key); },
  locality() {
    const p = this.prov(); if (p.cat === 'local') return 'local'; if (p.cat === 'router') return 'router';
    if (p.cat === 'custom') { try { const h = new URL(this.baseUrl()).hostname; if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\])/.test(h) || h.endsWith('.local')) return 'local'; } catch (e) {} return 'cloud'; }
    return 'cloud';
  },
  label() { return `${this.prov().name} · ${this.cfg.model || this.cfg.extra.deployment || '?'}`; },
};
AI.load();

/* ---------------- penyamaran data sensitif ---------------- */
function aiRedact(text) {
  if (!AI.cfg.redact) return text;
  const map = new Map(); let n = 0;
  return text.replace(/\b(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, ip => { if (!map.has(ip)) map.set(ip, `[IP-INTERNAL-${++n}]`); return map.get(ip); })
    .replace(/\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, '[MAC]');
}

/* ---------------- klien HTTP ---------------- */
function aiHeaders(extra = {}) {
  const p = AI.prov(); const h = { 'Content-Type': 'application/json', ...(p.headers || {}), ...extra };
  if (AI.cfg.headers.trim()) { try { Object.assign(h, JSON.parse(AI.cfg.headers)); } catch (e) { throw new Error('Header tambahan bukan JSON yang valid.'); } }
  return h;
}
async function aiFetch(url, opt, timeoutMs = 120000) {
  const ctl = new AbortController(); const tm = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { ...opt, signal: ctl.signal });
    const txt = await r.text(); let js = null; try { js = JSON.parse(txt); } catch (e) {}
    if (!r.ok) {
      const msg = js?.error?.message || js?.error?.toString?.() || js?.message || txt.slice(0, 300);
      throw new Error(`HTTP ${r.status}: ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`);
    }
    return js ?? txt;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Waktu habis (timeout) menunggu jawaban penyedia AI.');
    if (e instanceof TypeError) throw new Error('Gagal terhubung ke ' + url.split('?')[0] + '. Periksa base URL, pastikan server berjalan, dan izinkan CORS untuk halaman ini' +
      (AI.prov().id === 'ollama' ? ' (set OLLAMA_ORIGINS=* lalu restart Ollama).' : '.'));
    throw e;
  } finally { clearTimeout(tm); }
}

async function aiListModels() {
  const p = AI.prov(), b = AI.baseUrl();
  if (p.style === 'azure') throw new Error('Azure OpenAI memakai nama deployment, bukan daftar model.');
  if (p.noList) throw new Error('Penyedia ini tidak menyediakan endpoint daftar model; pilih dari preset atau ketik manual.');
  const h = p.style === 'anthropic'
    ? aiHeaders({ 'x-api-key': AI.key, 'anthropic-version': '2023-06-01', 'anthropic-dangerous-direct-browser-access': 'true' })
    : aiHeaders(AI.key ? { Authorization: 'Bearer ' + AI.key } : {});
  delete h['Content-Type'];
  const js = await aiFetch(b + '/models' + (p.style === 'anthropic' ? '?limit=100' : ''), { headers: h }, 30000);
  const arr = js.data || js.models || [];
  return arr.map(m => typeof m === 'string' ? m : (m.id || m.name)).filter(Boolean).sort();
}

// messages: [{role:'user'|'assistant', content:string}]
async function aiChat(messages, system, opts = {}) {
  const p = AI.prov(), b = AI.baseUrl(), maxT = +opts.maxTokens || +AI.cfg.maxTokens || 2048;
  const temp = AI.cfg.temperature === '' || p.noTemp ? undefined : +AI.cfg.temperature;
  if (p.style === 'anthropic') {
    // Model Claude terbaru selalu "berpikir" (adaptive thinking) dan token berpikir dihitung dalam max_tokens → beri ruang cukup.
    const body = { model: AI.cfg.model, max_tokens: Math.max(maxT, 8000), system, messages };
    if (p.id === 'anthropic') body.output_config = { effort: 'low' };
    const js = await aiFetch(b + '/messages', { method: 'POST', body: JSON.stringify(body),
      headers: aiHeaders({ 'x-api-key': AI.key, 'anthropic-version': '2023-06-01', 'anthropic-dangerous-direct-browser-access': 'true' }) });
    if (js.stop_reason === 'refusal') throw new Error('Model menolak permintaan ini (stop_reason: refusal).');
    const out = (js.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n').trim();
    if (!out) throw new Error(`Respons kosong (stop_reason: ${js.stop_reason}). Coba naikkan Maks. token.`);
    return out;
  }
  const msgs = [{ role: 'system', content: system }, ...messages];
  const body = { model: AI.cfg.model, messages: msgs };
  body[p.tokenParam || 'max_tokens'] = maxT; if (temp !== undefined && !isNaN(temp)) body.temperature = temp;
  let url = b + '/chat/completions', h = aiHeaders(AI.key ? { Authorization: 'Bearer ' + AI.key } : {});
  if (p.style === 'azure') {
    url = `${b}/openai/deployments/${encodeURIComponent(AI.cfg.extra.deployment || '')}/chat/completions?api-version=${encodeURIComponent(AI.cfg.extra.apiVersion || '2024-10-21')}`;
    h = aiHeaders({ 'api-key': AI.key }); delete body.model;
  }
  const js = await aiFetch(url, { method: 'POST', body: JSON.stringify(body), headers: h });
  const c = js.choices?.[0]; const txt = c?.message?.content;
  if (txt == null || txt === '') throw new Error('Respons kosong dari model' + (c?.finish_reason ? ` (finish_reason: ${c.finish_reason})` : '') + '.');
  return (Array.isArray(txt) ? txt.map(x => x.text || '').join('') : txt).replace(/<think>[\s\S]*?<\/think>/g, '').trim();
}

/* ---------------- konteks & prompt ---------------- */
const AI_SYSTEM = `Anda adalah SENTINEL-AI, analis keamanan siber senior yang membantu Perwira Siber satuan TNI AD.
Aturan:
- Jawab dalam Bahasa Indonesia yang baku, ringkas, dan operasional.
- Gunakan HANYA data yang diberikan (insiden, peringatan, aset, MITRE ATT&CK). Jangan mengarang IoC, CVE, nama pelaku, atau fakta lain; tulis "tidak ada data" bila informasi tidak tersedia.
- Bedakan fakta (dari data) dan dugaan/analisis (beri label "Analisis:").
- Prioritaskan keselamatan operasi: ketersediaan catu daya, komunikasi, dan pengamanan markas.
- Seluruh data adalah lingkungan simulasi latihan.`;

function aiIncidentContext(inc, engine) {
  const L = [`INSIDEN ${inc.id} — ${inc.title}`, `Status: ${inc.status} | Skor risiko: ${inc.score}/100 | Melibatkan OT: ${inc.ot ? 'ya' : 'tidak'}`,
    `Tahapan kill chain: ${inc.tactics.join(' → ') || '-'}`,
    `Teknik MITRE: ${[...inc.techs].map(t => `${t} ${MITRE[t].name} (${MITRE[t].dom})`).join('; ') || '-'}`,
    `Aset: ${[...inc.assets].map(id => { const a = ASSET_BY_ID[id]; return a ? `${id} (${a.name}, ${a.ip}, zona ${a.zone}, kekritisan ${a.crit}/5${engine.isolated.has(id) ? ', DIISOLASI' : ''})` : id; }).join('; ')}`,
    'Kronologi peringatan:'];
  inc.alerts.forEach(a => L.push(`- ${wib(a.ts)} [${SEV_LABEL[SEV[a.sev]]}] ${a.title}. ${a.detail}`));
  L.push('Tindakan yang sudah diambil: ' + (inc.actions.map(a => a.text).join(' | ') || 'belum ada'));
  return aiRedact(L.join('\n'));
}
function aiSituationContext(engine) {
  const act = engine.incidents;
  const L = [`Postur keamanan satuan: ${engine.posture()}/100. Insiden: ${act.length} (aktif ${act.filter(i => i.status === 'Aktif').length}). Peringatan: ${engine.alerts.length}.`];
  act.forEach(i => L.push(`- ${i.id} [${i.status}, skor ${i.score}] ${i.title}; aset: ${[...i.assets].join(', ')}; teknik: ${[...i.techs].join(', ')}`));
  L.push('Aset berisiko tertinggi: ' + ASSETS.filter(a => a.id !== 'INET').map(a => [a.id, engine.assetRisk(a.id)]).sort((x, y) => y[1] - x[1]).slice(0, 6).map(x => `${x[0]} (${x[1]})`).join(', '));
  return aiRedact(L.join('\n'));
}
const AI_TASKS = {
  analyze: ctx => `Analisis insiden berikut untuk Perwira Siber. Susun jawaban dengan judul bagian:
1. Ringkasan eksekutif (2–3 kalimat untuk Dansat)
2. Rekonstruksi serangan (urutan langkah penyerang, kaitkan dengan teknik MITRE)
3. Penilaian dampak terhadap operasi satuan
4. Langkah respons prioritas (bernomor, paling mendesak dulu, sebutkan aset/IP)
5. Indikator yang perlu diburu (threat hunting) di aset lain
6. Tingkat keyakinan analisis & data yang masih dibutuhkan

DATA:
${ctx}`,
  report: (ctx, draft) => `Berikut draf Laporan Khusus (LAPSUS) insiden siber yang dibuat otomatis dari templat, beserta data insidennya.
Sempurnakan draf tersebut: pertahankan struktur, nomor, kop, dan format naskah dinas (bagian 1–9), perbaiki bahasa agar lebih runtut dan formal,
perkaya bagian "POKOK KEJADIAN", "ANALISIS DAMPAK", dan "SARAN / REKOMENDASI" berdasarkan data. Jangan menambah fakta yang tidak ada di data.
Keluarkan HANYA teks laporan final tanpa komentar tambahan dan tanpa format markdown.

DATA INSIDEN:
${ctx}

DRAF LAPSUS:
${draft}`,
  logs: ctx => `Berikut hasil analisis log forensik otomatis. Jelaskan temuan untuk analis: apa yang terjadi, seberapa serius, keterkaitan antar-temuan, dan langkah verifikasi/penanganan berikutnya.

TEMUAN:
${ctx}`,
};

/* ---------------- render markdown sederhana (aman) ---------------- */
function aiMd(t) {
  const e = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  return e(t).replace(/^#{1,4}\s*(.+)$/gm, '<h4>$1</h4>').replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^\s*[-*]\s+(.+)$/gm, '<li>$1</li>').replace(/(<li>[\s\S]*?<\/li>)(?!\s*<li>)/g, '<ul>$1</ul>').replace(/\n{2,}/g, '<br><br>').replace(/\n/g, '<br>')
    .replace(/<br>(<\/?(ul|li|h4))/g, '$1').replace(/(<\/(ul|h4)>)<br>/g, '$1');
}
