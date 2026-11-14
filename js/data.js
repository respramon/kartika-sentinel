/* KARTIKA-SENTINEL — data inventaris aset, basis pengetahuan MITRE ATT&CK, dan IoC lokal.
 * Seluruh data bersifat SIMULASI untuk keperluan purwarupa (bukan data satuan nyata). */
'use strict';

const ZONES = {
  ext: { name: 'INTERNET', x: 10, y: 20, w: 120, h: 400, color: 'var(--zone-ext)' },
  dmz: { name: 'PERIMETER / DMZ', x: 150, y: 20, w: 130, h: 400, color: 'var(--zone-dmz)' },
  it:  { name: 'ZONA IT SATUAN', x: 300, y: 20, w: 280, h: 400, color: 'var(--zone-it)' },
  ot:  { name: 'ZONA OT / IoT MARKAS', x: 600, y: 20, w: 290, h: 400, color: 'var(--zone-ot)' },
};

// criticality: 1 (rendah) – 5 (vital bagi operasi satuan)
const ASSETS = [
  { id: 'INET', name: 'Internet', ip: '0.0.0.0/0', zone: 'ext', type: 'cloud', crit: 0, x: 70, y: 210, os: '-', vulns: [] },
  { id: 'FW-01', name: 'Firewall / Gateway', ip: '10.10.0.1', zone: 'dmz', type: 'firewall', crit: 5, x: 215, y: 130, os: 'pfSense 2.7', vulns: [] },
  { id: 'SRV-MAIL', name: 'Server Surel', ip: '10.10.0.10', zone: 'dmz', type: 'server', crit: 3, x: 215, y: 290, os: 'Ubuntu 22.04', vulns: ['CVE-2023-4911'] },
  { id: 'SRV-AD', name: 'Domain Controller', ip: '10.10.1.10', zone: 'it', type: 'server', crit: 5, x: 350, y: 80, os: 'Windows Server 2019', vulns: ['CVE-2020-1472'] },
  { id: 'SRV-FILE', name: 'Server Berkas Staf', ip: '10.10.1.11', zone: 'it', type: 'server', crit: 4, x: 450, y: 80, os: 'Windows Server 2019', vulns: [] },
  { id: 'SRV-MON', name: 'Server SENTINEL', ip: '10.10.1.5', zone: 'it', type: 'sentinel', crit: 4, x: 540, y: 80, os: 'Debian 12 (air-gapped)', vulns: [] },
  { id: 'WS-STAF-01', name: 'PC Staf Ops', ip: '10.10.1.21', zone: 'it', type: 'workstation', crit: 3, x: 340, y: 210, os: 'Windows 10', vulns: [] },
  { id: 'WS-STAF-02', name: 'PC Staf Pers', ip: '10.10.1.22', zone: 'it', type: 'workstation', crit: 2, x: 430, y: 210, os: 'Windows 10', vulns: ['CVE-2023-36884'] },
  { id: 'WS-STAF-03', name: 'PC Staf Log', ip: '10.10.1.23', zone: 'it', type: 'workstation', crit: 2, x: 520, y: 210, os: 'Windows 10', vulns: [] },
  { id: 'WS-STAF-04', name: 'PC Staf Intel', ip: '10.10.1.24', zone: 'it', type: 'workstation', crit: 4, x: 385, y: 330, os: 'Windows 11', vulns: [] },
  { id: 'WIFI-AP', name: 'Access Point Markas', ip: '10.10.1.2', zone: 'it', type: 'ap', crit: 2, x: 500, y: 330, os: 'OpenWrt 23', vulns: [] },
  { id: 'WS-ENG', name: 'Workstation Teknisi OT', ip: '10.10.20.5', zone: 'ot', type: 'workstation', crit: 4, x: 650, y: 80, os: 'Windows 10 LTSC', vulns: [] },
  { id: 'PLC-GENSET', name: 'PLC Genset Utama', ip: '10.10.20.10', zone: 'ot', type: 'plc', crit: 5, x: 750, y: 80, os: 'Modbus/TCP PLC', vulns: ['CVE-2022-29965'] },
  { id: 'UPS-01', name: 'UPS Ruang Server', ip: '10.10.20.11', zone: 'ot', type: 'ups', crit: 4, x: 845, y: 80, os: 'SNMP Card', vulns: [] },
  { id: 'NVR-01', name: 'Perekam CCTV (NVR)', ip: '10.10.20.30', zone: 'ot', type: 'nvr', crit: 3, x: 650, y: 210, os: 'Embedded Linux', vulns: [] },
  { id: 'CCTV-01', name: 'CCTV Gerbang', ip: '10.10.20.31', zone: 'ot', type: 'camera', crit: 3, x: 745, y: 210, os: 'BusyBox', vulns: [] },
  { id: 'CCTV-02', name: 'CCTV Gudang Senjata', ip: '10.10.20.32', zone: 'ot', type: 'camera', crit: 4, x: 845, y: 210, os: 'BusyBox', vulns: ['Kredensial bawaan'] },
  { id: 'AKSES-01', name: 'Kontrol Akses Gerbang', ip: '10.10.20.40', zone: 'ot', type: 'access', crit: 4, x: 700, y: 330, os: 'Embedded RTOS', vulns: [] },
  { id: 'RADIO-GW', name: 'Gateway Radio-over-IP', ip: '10.10.20.50', zone: 'ot', type: 'radio', crit: 5, x: 820, y: 330, os: 'Embedded Linux', vulns: [] },
];
const ASSET_BY_ID = Object.fromEntries(ASSETS.map(a => [a.id, a]));
const ASSET_BY_IP = Object.fromEntries(ASSETS.map(a => [a.ip, a]));
const KNOWN_MACS = new Set(ASSETS.map((a, i) => 'a4:5e:60:' + (0x10 + i).toString(16) + ':0c:01'));

// Basis pengetahuan MITRE ATT&CK (subset relevan) — Enterprise & ICS
const MITRE = {
  'T1595': { name: 'Active Scanning', tactic: 'Reconnaissance', dom: 'Enterprise' },
  'T1566.001': { name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access', dom: 'Enterprise' },
  'T1200': { name: 'Hardware Additions', tactic: 'Initial Access', dom: 'Enterprise' },
  'T1078.001': { name: 'Valid Accounts: Default Accounts', tactic: 'Initial Access', dom: 'Enterprise' },
  'T1204.002': { name: 'User Execution: Malicious File', tactic: 'Execution', dom: 'Enterprise' },
  'T1059.001': { name: 'Command & Scripting: PowerShell', tactic: 'Execution', dom: 'Enterprise' },
  'T1110': { name: 'Brute Force', tactic: 'Credential Access', dom: 'Enterprise' },
  'T1078': { name: 'Valid Accounts', tactic: 'Persistence', dom: 'Enterprise' },
  'T1557.002': { name: 'Adversary-in-the-Middle: ARP Cache Poisoning', tactic: 'Credential Access', dom: 'Enterprise' },
  'T1046': { name: 'Network Service Discovery', tactic: 'Discovery', dom: 'Enterprise' },
  'T1021.002': { name: 'Remote Services: SMB/Admin Shares', tactic: 'Lateral Movement', dom: 'Enterprise' },
  'T1071.001': { name: 'App Layer Protocol: Web (C2 Beacon)', tactic: 'Command and Control', dom: 'Enterprise' },
  'T1071.004': { name: 'App Layer Protocol: DNS', tactic: 'Command and Control', dom: 'Enterprise' },
  'T1048': { name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', dom: 'Enterprise' },
  'T1486': { name: 'Data Encrypted for Impact', tactic: 'Impact', dom: 'Enterprise' },
  'T1498': { name: 'Network Denial of Service', tactic: 'Impact', dom: 'Enterprise' },
  'T0883': { name: 'Internet Accessible Device', tactic: 'Initial Access', dom: 'ICS' },
  'T0812': { name: 'Default Credentials', tactic: 'Lateral Movement', dom: 'ICS' },
  'T0846': { name: 'Remote System Discovery', tactic: 'Discovery', dom: 'ICS' },
  'T0888': { name: 'Remote System Information Discovery', tactic: 'Discovery', dom: 'ICS' },
  'T0801': { name: 'Monitor Process State', tactic: 'Collection', dom: 'ICS' },
  'T0855': { name: 'Unauthorized Command Message', tactic: 'Impair Process Control', dom: 'ICS' },
  'T0836': { name: 'Modify Parameter', tactic: 'Impair Process Control', dom: 'ICS' },
  'T0831': { name: 'Manipulation of Control', tactic: 'Impact', dom: 'ICS' },
  'T0826': { name: 'Loss of Availability', tactic: 'Impact', dom: 'ICS' },
  // teknik tambahan yang dipantau (cakupan aturan pengembangan lanjut)
  'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access', dom: 'Enterprise' },
  'T1133': { name: 'External Remote Services', tactic: 'Initial Access', dom: 'Enterprise' },
  'T1053': { name: 'Scheduled Task/Job', tactic: 'Execution', dom: 'Enterprise' },
  'T1136': { name: 'Create Account', tactic: 'Persistence', dom: 'Enterprise' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access', dom: 'Enterprise' },
  'T1018': { name: 'Remote System Discovery', tactic: 'Discovery', dom: 'Enterprise' },
  'T1570': { name: 'Lateral Tool Transfer', tactic: 'Lateral Movement', dom: 'Enterprise' },
  'T0843': { name: 'Program Download', tactic: 'Lateral Movement', dom: 'ICS' },
  'T1005': { name: 'Data from Local System', tactic: 'Collection', dom: 'Enterprise' },
  'T0861': { name: 'Point & Tag Identification', tactic: 'Collection', dom: 'ICS' },
  'T0869': { name: 'Standard Application Layer Protocol', tactic: 'Command and Control', dom: 'ICS' },
  'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', dom: 'Enterprise' },
  'T0806': { name: 'Brute Force I/O', tactic: 'Impair Process Control', dom: 'ICS' },
  'T1490': { name: 'Inhibit System Recovery', tactic: 'Impact', dom: 'Enterprise' },
  'T0813': { name: 'Denial of Control', tactic: 'Impact', dom: 'ICS' },
};
const TACTIC_ORDER = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impair Process Control', 'Impact'];
const TACTIC_ID = {
  'Reconnaissance': 'Pengintaian', 'Initial Access': 'Akses Awal', 'Execution': 'Eksekusi', 'Persistence': 'Persistensi',
  'Credential Access': 'Pencurian Kredensial', 'Discovery': 'Penjelajahan', 'Lateral Movement': 'Pergerakan Lateral',
  'Collection': 'Pengumpulan', 'Command and Control': 'Komando & Kendali (C2)', 'Exfiltration': 'Eksfiltrasi',
  'Impair Process Control': 'Gangguan Kendali Proses', 'Impact': 'Dampak',
};

// IoC lokal (feed intelijen ancaman yang disinkronkan secara offline / sneakernet)
const LOCAL_IOC = {
  ips: { '185.220.101.47': 'Node C2 (APT-simulasi)', '45.95.147.12': 'Pemindai Mirai', '194.26.29.113': 'Infrastruktur botnet' },
  domains: { 'upd-cdn-sync.net': 'Domain tunneling DNS', 'office-dokumen.id-update.com': 'Domain phishing' },
};

const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEV_LABEL = ['INFO', 'RENDAH', 'SEDANG', 'TINGGI', 'KRITIS'];
