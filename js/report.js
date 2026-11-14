/* KARTIKA-SENTINEL — Generator Laporan Khusus (LAPSUS) Insiden Siber otomatis (Bahasa Indonesia)
 * Natural Language Generation berbasis templat + pengetahuan MITRE; berjalan 100% lokal. */
'use strict';

const SIM_START = Date.parse('2026-11-14T08:00:00+07:00');
const BULAN = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];
const ROMAWI = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X', 'XI', 'XII'];
function toDate(ts) { return new Date(ts > 1e9 ? ts * 1000 : SIM_START + ts * 1000); }
function wib(ts, withDate = false) {
  const d = new Date(toDate(ts).getTime() + 7 * 3600e3);
  const hh = String(d.getUTCHours()).padStart(2, '0'), mm = String(d.getUTCMinutes()).padStart(2, '0'), ss = String(d.getUTCSeconds()).padStart(2, '0');
  return withDate ? `${d.getUTCDate()} ${BULAN[d.getUTCMonth()]} ${d.getUTCFullYear()} pukul ${hh}.${mm}.${ss} WIB` : `${hh}:${mm}:${ss}`;
}

const RECO = {
  T1566: 'Tingkatkan penyaringan lampiran makro di server surel dan lakukan pelatihan kesadaran phishing bagi personel staf.',
  T1204: 'Terapkan kebijakan blokir makro dari internet (Group Policy) dan Attack Surface Reduction pada seluruh PC staf.',
  T1059: 'Aktifkan PowerShell Constrained Language Mode dan logging Script Block (Event ID 4104).',
  T1110: 'Terapkan penguncian akun setelah 5 kegagalan, autentikasi multi-faktor untuk akun administratif, dan kata sandi minimal 14 karakter.',
  T1078: 'Reset seluruh kredensial akun yang terdampak dan audit hak akses (prinsip least privilege).',
  T1021: 'Nonaktifkan share administratif (ADMIN$/C$) pada PC staf dan batasi SMB antar-workstation melalui firewall host.',
  T1486: 'Pulihkan data dari cadangan offline terakhir yang terverifikasi; terapkan cadangan 3-2-1 dengan salinan air-gapped.',
  T1071: 'Blokir domain/IP C2 di firewall dan DNS sinkhole; perbarui feed IoC lokal di seluruh sensor.',
  T1048: 'Paksa seluruh resolusi DNS melalui resolver internal dan blokir DNS keluar langsung (port 53) dari zona staf.',
  T1046: 'Segmentasi jaringan IT–OT dengan firewall industri dan aturan default-deny; hanya workstation teknisi yang boleh menjangkau zona OT.',
  T1595: 'Tutup layanan yang tidak perlu terekspos ke internet; tinjau aturan NAT/port-forward pada gateway.',
  T1498: 'Terapkan pembatasan laju (rate limiting) keluar per perangkat IoT dan blokir lalu lintas keluar non-esensial dari zona OT.',
  T1557: 'Aktifkan Dynamic ARP Inspection dan DHCP Snooping pada switch; terapkan 802.1X untuk akses jaringan.',
  T1200: 'Terapkan Network Access Control (NAC) dan daftar putih MAC pada Access Point markas.',
  T0812: 'Ganti seluruh kredensial bawaan perangkat IoT/OT, nonaktifkan Telnet, dan perbarui firmware kamera.',
  T0883: 'Pastikan tidak ada perangkat OT/IoT yang dapat diakses langsung dari internet; gunakan VPN dengan MFA untuk akses jarak jauh.',
  T0846: 'Pasang sensor pasif di zona OT dan buat daftar putih komunikasi (allow-list) per protokol industri.',
  T0888: 'Batasi fungsi diagnostik Modbus (FC43) hanya untuk workstation teknisi.',
  T0801: 'Batasi pembacaan register proses hanya dari HMI/workstation teknisi yang terdaftar.',
  T0855: 'Aktifkan mode RUN-LOCK/kunci kunci fisik pada PLC dan terapkan firewall Modbus yang hanya mengizinkan fungsi baca dari host tak berwenang.',
  T0836: 'Verifikasi dan kembalikan seluruh parameter PLC ke konfigurasi baseline yang ditandatangani; lakukan pemeriksaan fisik genset.',
  T0831: 'Siapkan prosedur operasi manual genset dan uji pemindahan beban ke sumber cadangan.',
  T0826: 'Aktifkan sumber daya cadangan untuk sistem vital (komunikasi, server, keamanan perimeter).',
};

function buildReport(inc, eng, meta = {}) {
  const no = `LAPSUS/${inc.id.split('-')[1]}/SIBER/${ROMAWI[toDate(inc.first).getUTCMonth()]}/2026`;
  const sevTxt = SEV_LABEL[inc.sev];
  const assets = [...inc.assets].map(id => ASSET_BY_ID[id]).filter(Boolean);
  const techs = [...inc.techs];
  const extIps = [...new Set(inc.alerts.flatMap(a => [a.ev.srcIp, a.ev.dstIp]).filter(Boolean))];
  const doms = [...new Set(inc.alerts.map(a => a.ev.query && a.ev.query.split('.').slice(-2).join('.')).filter(Boolean))];
  const users = [...new Set(inc.alerts.map(a => a.ev.user).filter(Boolean))];
  const otHit = assets.filter(a => a.zone === 'ot');
  const L = [];
  L.push('RAHASIA — SIMULASI LATIHAN');
  L.push('');
  L.push(`${meta.unit || 'SATUAN SIMULASI (YONIF 000/KARTIKA)'}`);
  L.push('SEKSI SIBER');
  L.push('');
  L.push(`Nomor       : ${no}`);
  L.push(`Klasifikasi : Rahasia`);
  L.push(`Derajat     : ${inc.sev >= 4 ? 'KILAT' : inc.sev >= 3 ? 'SEGERA' : 'BIASA'}`);
  L.push(`Kepada      : Yth. Danpussiberad u.p. Pusat Operasi Siber`);
  L.push(`Tembusan    : Dansat; Pasi Intel; Pasi Ops`);
  L.push(`Perihal     : Laporan Khusus Insiden Siber — ${inc.title}`);
  L.push('');
  L.push('1.  POKOK KEJADIAN');
  L.push(`    Pada ${wib(inc.first, true)}, sistem KARTIKA-SENTINEL mendeteksi insiden siber ${inc.ot ? 'yang melibatkan infrastruktur OT/IoT markas ' : ''}dengan tingkat keparahan ${sevTxt} (skor risiko ${inc.score}/100). ` +
    `Insiden terdiri atas ${inc.alerts.length} peringatan terkorelasi` + (inc.tactics.length ? ` yang mencakup ${inc.tactics.length} tahapan serangan (${inc.tactics.map(t => TACTIC_ID[t]).join(' → ')}).` : ' berupa anomali perilaku yang terdeteksi model AI dan memerlukan verifikasi analis.'));
  L.push('');
  L.push('2.  KRONOLOGIS');
  inc.alerts.forEach((a, i) => L.push(`    ${String.fromCharCode(97 + (i % 26))}.  ${wib(a.ts)}  [${SEV_LABEL[SEV[a.sev]]}] ${a.title}. ${a.detail}`));
  L.push('');
  L.push('3.  ASET TERDAMPAK');
  assets.forEach((a, i) => L.push(`    ${String.fromCharCode(97 + i)}.  ${a.id} — ${a.name} (${a.ip}, ${a.zone === 'ot' ? 'zona OT/IoT' : a.zone === 'dmz' ? 'perimeter' : 'zona IT'}, kekritisan ${a.crit}/5)${eng.isolated.has(a.id) ? ' — TELAH DIISOLASI' : ''}.`));
  L.push('');
  L.push('4.  TEKNIK SERANGAN (MITRE ATT&CK)');
  if (!techs.length) L.push('    Belum dapat dipetakan — anomali perilaku tanpa tanda tangan serangan yang dikenal.');
  techs.sort().forEach((t, i) => L.push(`    ${String.fromCharCode(97 + i)}.  ${t} ${MITRE[t].name} — taktik ${TACTIC_ID[MITRE[t].tactic]} (${MITRE[t].dom}).`));
  L.push('');
  L.push('5.  INDIKATOR KOMPROMI (IoC)');
  if (extIps.length) L.push(`    a.  Alamat IP eksternal : ${extIps.join(', ')}`);
  if (doms.length) L.push(`    ${extIps.length ? 'b' : 'a'}.  Domain             : ${doms.join(', ')}`);
  if (users.length) L.push(`    -   Akun terlibat      : ${users.join(', ')}`);
  if (!extIps.length && !doms.length && !users.length) L.push('    Tidak ada IoC eksternal; sumber ancaman berasal dari jaringan internal.');
  L.push('');
  L.push('6.  ANALISIS DAMPAK');
  const dmp = [];
  if (techs.includes('T1486')) dmp.push('kerahasiaan dan ketersediaan dokumen staf terganggu akibat enkripsi ransomware');
  if (techs.some(t => ['T0855', 'T0836', 'T0831', 'T0826'].includes(t))) dmp.push('kendali genset utama dimanipulasi sehingga berpotensi memutus catu daya bagi sistem komunikasi dan keamanan markas');
  if (techs.includes('T1048')) dmp.push('terdapat indikasi kebocoran informasi dari PC Staf Intel ke pihak luar');
  if (techs.includes('T1498')) dmp.push('perangkat CCTV gudang senjata dikuasai pihak luar sehingga pengawasan visual tidak dapat dipercaya dan perangkat dipakai menyerang pihak ketiga');
  if (techs.includes('T1557.002')) dmp.push('lalu lintas staf berpotensi disadap (man-in-the-middle) termasuk kredensial');
  if (techs.includes('T1110') || techs.includes('T1078')) dmp.push('kredensial akun berisiko telah dikuasai penyerang');
  if (!dmp.length) dmp.push('dampak masih terbatas pada tahap pengintaian, belum ditemukan gangguan operasional');
  L.push(`    Berdasarkan analisis otomatis, ${dmp.join('; ')}. ` +
    `Aset dengan kekritisan tertinggi yang terlibat adalah ${assets.slice().sort((a, b) => b.crit - a.crit)[0]?.id || '-'}.`);
  L.push('');
  L.push('7.  TINDAKAN YANG TELAH DIAMBIL');
  if (inc.actions.length) inc.actions.forEach((a, i) => L.push(`    ${String.fromCharCode(97 + i)}.  ${wib(a.ts)}  ${a.text}`));
  else L.push('    Belum ada tindakan penanggulangan. Insiden masih AKTIF.');
  L.push(`    Status insiden saat laporan dibuat: ${inc.status.toUpperCase()}.`);
  L.push('');
  L.push('8.  SARAN / REKOMENDASI');
  const seen = new Set(); let k = 0;
  techs.forEach(t => { const key = t.split('.')[0]; if (RECO[key] && !seen.has(key)) { seen.add(key); L.push(`    ${String.fromCharCode(97 + k++)}.  ${RECO[key]}`); } });
  L.push(`    ${String.fromCharCode(97 + k)}.  Simpan seluruh bukti digital (log, image disk, PCAP) dengan rantai kustodi untuk analisis forensik lanjutan oleh Pussiberad.`);
  L.push('');
  L.push('9.  PENUTUP');
  L.push('    Demikian laporan khusus ini disampaikan sebagai bahan pertimbangan dan tindak lanjut Komando Atas.');
  L.push('');
  L.push(`                                         ${wib(Date.now() / 1000, true).replace(/ pukul.*/, '')}`);
  L.push('                                         Perwira Siber Satuan,');
  L.push('');
  L.push('');
  L.push('                                         ( ...................... )');
  L.push('');
  L.push('— Draf dibuat otomatis oleh KARTIKA-SENTINEL. Wajib diverifikasi Perwira Siber sebelum dikirim. —');
  return L.join('\n');
}

function buildStix(inc) {
  const now = new Date().toISOString();
  const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 3 | 8)).toString(16); });
  const objs = [];
  const ips = [...new Set(inc.alerts.flatMap(a => [a.ev.srcIp, a.ev.dstIp]).filter(Boolean))];
  const doms = [...new Set(inc.alerts.map(a => a.ev.query && a.ev.query.split('.').slice(-2).join('.')).filter(Boolean))];
  ips.forEach(ip => objs.push({ type: 'indicator', spec_version: '2.1', id: 'indicator--' + uuid(), created: now, modified: now, name: 'IP berbahaya ' + ip, pattern: `[ipv4-addr:value = '${ip}']`, pattern_type: 'stix', valid_from: now }));
  doms.forEach(d => objs.push({ type: 'indicator', spec_version: '2.1', id: 'indicator--' + uuid(), created: now, modified: now, name: 'Domain berbahaya ' + d, pattern: `[domain-name:value = '${d}']`, pattern_type: 'stix', valid_from: now }));
  [...inc.techs].forEach(t => objs.push({ type: 'attack-pattern', spec_version: '2.1', id: 'attack-pattern--' + uuid(), created: now, modified: now, name: MITRE[t].name,
    external_references: [{ source_name: MITRE[t].dom === 'ICS' ? 'mitre-ics-attack' : 'mitre-attack', external_id: t }] }));
  return JSON.stringify({ type: 'bundle', id: 'bundle--' + uuid(), objects: objs }, null, 2);
}
