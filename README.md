# KARTIKA-SENTINEL 🛡️

**Sistem Penangkalan Siber Satuan berbasis AI — IT + OT/IoT markas, air-gapped.**
Purwarupa untuk **Kartika Cyber Hackathon 2026**, kategori **Penangkalan**, oleh **Tim siberian**.

**Demo langsung:** https://respramon.github.io/kartika-sentinel/ · **Video demo:** https://youtu.be/FaV6W15-9GQ · **Slide:** [docs/KARTIKA-SENTINEL-slides.pdf](docs/KARTIKA-SENTINEL-slides.pdf)

> Satu mini-PC + satu port mirror = SOC mini untuk satuan TNI AD: mendeteksi serangan pada jaringan staf **dan** perangkat fisik markas (genset, CCTV, kontrol akses, radio IP), memetakan ke MITRE ATT&CK, memberi langkah respons, dan menulis Laporan Khusus (LAPSUS) insiden secara otomatis — tanpa internet, tanpa cloud asing.

## Masalah
1. Markas modern bergantung pada sistem **OT/IoT** (PLC genset, UPS, CCTV, akses gerbang, radio-over-IP) yang jarang dipantau, padahal serangan ke sistem ini berdampak **fisik** (catu daya padam, pengawasan buta).
2. Tidak setiap satuan memiliki personel SOC; deteksi tanpa interpretasi dan **pelaporan berjenjang yang cepat** tidak berguna.
3. Solusi SIEM komersial mahal, berat, dan sering bergantung pada **cloud luar negeri** — tidak sesuai untuk lingkungan militer.

## Solusi & fitur
| Fitur | Keterangan |
|---|---|
| Peta jaringan langsung | Zona Internet, DMZ, IT satuan, OT/IoT; aliran lalu lintas normal/serangan/diblokir dianimasikan |
| Mesin deteksi hibrida | 16 aturan gaya Sigma (Modbus/TCP, SMB, Kerberos, DNS, HTTP, Telnet, ARP/DHCP, proses endpoint) |
| **AI deteksi anomali** | Ensemble **Isolation Forest** + deviasi-z terhadap **baseline per-aset** (7 fitur perilaku per jendela 10 detik), dengan penjelasan fitur penyebab (explainable) |
| Analitik khusus | Entropi Shannon untuk DNS tunneling, koefisien variasi untuk beacon C2, IoC lokal |
| Korelasi insiden | Alert → insiden berdasarkan aset/IP & waktu; rantai kill chain; skor risiko 0–100 |
| MITRE ATT&CK Enterprise + **ICS** | Matriks heatmap teknik yang terdeteksi |
| Respons (SOAR) | Isolasi host, blokir IP, reset kredensial, RUN-LOCK PLC; mode otomatis untuk insiden KRITIS |
| **LAPSUS otomatis** | Laporan Khusus berformat naskah dinas (nomor, derajat KILAT/SEGERA, kronologis, IoC, dampak, rekomendasi) — unduh .txt / cetak PDF |
| Ekspor STIX 2.1 | Berbagi IoC ke tingkat atas (Pussiberad / platform CTI) |
| Analisis log forensik | Unggah `auth.log` atau CSV sensor; dianalisis lokal di peramban |
| Cyber range | 5 skenario latihan: phishing→ransomware, sabotase genset Modbus, botnet CCTV, DNS exfiltration, rogue device + ARP spoofing |

## Arsitektur
```
[Sensor: port mirror / TAP, parser protokol IT & OT, agen endpoint, syslog OT]
        │
[Mesin Deteksi: 16 aturan + AI Isolation Forest (baseline per-aset) + entropi + IoC]
        │
[Korelasi & Skor Risiko: kill chain ATT&CK Enterprise+ICS × kekritisan aset]
        │
[Respons SOAR: isolasi, blokir, reset, RUN-LOCK]──►[LAPSUS otomatis + STIX 2.1 ke Komando Atas]
```

## Menjalankan
Tidak butuh instalasi atau internet. Buka `index.html` di peramban modern, atau:
```bash
python -m http.server 8080   # lalu buka http://localhost:8080
```
Tambahkan `?auto=1` pada URL untuk menjalankan semua skenario otomatis.

## Struktur kode
- `js/data.js` — inventaris aset (fiktif), basis pengetahuan MITRE ATT&CK, IoC lokal
- `js/engine.js` — generator lalu lintas, skenario serangan, aturan deteksi, Isolation Forest, korelasi
- `js/report.js` — generator LAPSUS & STIX 2.1
- `js/app.js` — antarmuka & simulasi waktu nyata

## Kelayakan implementasi
- Perangkat keras: mini-PC (±Rp 6–8 juta) + port mirror pada switch markas.
- Produksi: sensor diganti Zeek/Suricata + parser Modbus nyata; aturan dan model AI yang sama dipakai; baseline terbentuk otomatis 1–7 hari.
- Integrasi: syslog/STIX ke Wazuh/OpenCTI tingkat Kotama/Pussiberad.
- Pengembangan: ringkasan insiden dengan LLM open-weight lokal (mis. via Ollama), dasbor komando multi-satuan, aturan Sigma yang dapat diperbarui offline.

## Catatan kejujuran & atribusi
- Seluruh data jaringan, nama satuan, aset, IP, dan kejadian pada demo adalah **simulasi/fiktif**. Mesin deteksi, AI, korelasi, respons, dan laporan **berjalan sungguhan** atas data tersebut.
- Seluruh kode ditulis selama periode program, tanpa dependensi pihak ketiga (vanilla JS/CSS). Dibangun dengan bantuan asisten AI pemrograman.
- MITRE ATT&CK® adalah merek dagang The MITRE Corporation; digunakan sebagai taksonomi referensi.
- Algoritma Isolation Forest: Liu, Ting & Zhou (2008).

Lisensi: MIT.
