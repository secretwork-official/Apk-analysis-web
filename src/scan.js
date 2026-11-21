'use strict';
const AdmZip = require('adm-zip');
const forge = require('node-forge');
const ApkReader = require('node-apk-parser');

// Render's free plan gives this service only 0.15 vCPU. These caps keep one upload from
// pegging the CPU long enough to block the whole server (which can trip Render's health check
// and cause a restart). Lower on free tier; the worker-thread wrapper in server.js is the main
// fix (it stops a scan from blocking other requests), these caps are the second layer.
const MAX_TOTAL_SCAN = 18 * 1024 * 1024;     // cap total bytes string-scanned across all files
const MAX_FILE_SCAN = 6 * 1024 * 1024;       // cap per-file bytes scanned (dex/so can be huge)
const MAX_FINDINGS_PER_KIND = 500;

// ---------- string extraction (like `strings` over raw bytes) ----------
function extractAsciiStrings(buf, minLen = 5) {
  const out = []; let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i] : 0;
    const printable = c >= 32 && c <= 126;
    if (printable) { if (start === -1) start = i; }
    else { if (start !== -1 && i - start >= minLen) out.push(buf.toString('latin1', start, i)); start = -1; }
  }
  return out;
}
// also extract UTF-16LE strings (common inside classes.dex / native Java strings)
function extractUtf16Strings(buf, minLen = 5) {
  const out = []; let start = -1, count = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) {
    const lo = buf[i], hi = buf[i + 1];
    const printable = hi === 0 && lo >= 32 && lo <= 126;
    if (printable) { if (start === -1) { start = i; count = 0; } count++; }
    else { if (start !== -1 && count >= minLen) { let s = ''; for (let j = start; j < i; j += 2) s += String.fromCharCode(buf[j]); out.push(s); } start = -1; }
  }
  return out;
}

const RE = {
  url: /\bhttps?:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?(?:\/[^\s"'<>\\]{0,300})?/g,
  domain: /\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,4}(?:[A-Za-z]{2,24})\b/g,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
  base64: /\b(?:[A-Za-z0-9+\/]{4}){8,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\b/g,
  pem: /-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY|EC PRIVATE KEY|ENCRYPTED PRIVATE KEY|PUBLIC KEY|CERTIFICATE)-----[\s\S]{20,4000}?-----END \1-----/g,
  jwt: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
};
// known vendor key / secret patterns -> {severity, label}
const SECRET_PATTERNS = [
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, 'High', 'Google API key'],
  [/\b[0-9]{12}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b/g, 'Low', 'Google OAuth client ID (not secret by itself)'],
  [/\bAKIA[0-9A-Z]{16}\b/g, 'Critical', 'AWS Access Key ID'],
  [/\b(?:A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b/g, 'Critical', 'AWS key-family identifier'],
  [/\bAIzaSy[0-9A-Za-z_-]{33}\b/g, 'High', 'Firebase/Google API key'],
  [/\bsk_live_[0-9A-Za-z]{10,99}\b/g, 'Critical', 'Stripe LIVE secret key'],
  [/\bsk_test_[0-9A-Za-z]{10,99}\b/g, 'Medium', 'Stripe TEST secret key'],
  [/\brk_live_[0-9A-Za-z]{10,99}\b/g, 'Critical', 'Stripe restricted LIVE key'],
  [/\bxox[baprs]-[0-9A-Za-z-]{10,70}\b/g, 'Critical', 'Slack token'],
  [/\bgh[pousr]_[0-9A-Za-z]{30,255}\b/g, 'Critical', 'GitHub access token'],
  [/\bsq0(atp|csp)-[0-9A-Za-z_-]{20,50}\b/g, 'High', 'Square access/client token'],
  [/\bSK[0-9a-fA-F]{32}\b/g, 'High', 'Twilio API key'],
  [/\bAC[0-9a-fA-F]{32}\b/g, 'Low', 'Twilio Account SID'],
  [/\bghs_[0-9A-Za-z]{30,255}\b/g, 'Critical', 'GitHub App token'],
  [/\b(?:ya29\.[0-9A-Za-z_-]{20,120})\b/g, 'High', 'Google OAuth access token'],
  [/-----BEGIN RSA PRIVATE KEY-----/g, 'Critical', 'RSA private key'],
  [/-----BEGIN EC PRIVATE KEY-----/g, 'Critical', 'EC private key'],
  [/-----BEGIN PRIVATE KEY-----/g, 'Critical', 'Private key (PKCS8)'],
  [/\bmongodb(?:\+srv)?:\/\/[^\s"'<>]{6,300}/g, 'Critical', 'MongoDB connection string'],
  [/\bpostgres(?:ql)?:\/\/[^\s"'<>]{6,300}/g, 'Critical', 'PostgreSQL connection string'],
  [/\bmysql:\/\/[^\s"'<>]{6,300}/g, 'Critical', 'MySQL connection string'],
  [/(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["']([^"'\s]{6,100})["']/gi, 'Medium', 'Hardcoded credential-looking assignment'],
];

function shannonEntropy(s) {
  const freq = {}; for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0; for (const c in freq) { const p = freq[c] / s.length; h -= p * Math.log2(p); }
  return h;
}
const B64_PLAUSIBLE = /^[A-Za-z0-9+/]+={0,2}$/;
function looksLikeKeyMaterial(b64) {
  try { const buf = Buffer.from(b64, 'base64'); return buf.length >= 16 && buf.length <= 4096; } catch { return false; }
}

function isPrivateIp(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 0 || a >= 224;
}
const SKIP_DOMAIN_SUFFIX = /\.(png|jpg|jpeg|gif|webp|ttf|otf|xml|txt|so|dex|class|java|kt|json|proto)$/i;
const SCHEMA_HOSTS = new Set(['schemas.android.com', 'www.w3.org', 'xml.org', 'java.sun.com', 'schemas.microsoft.com']);
// Real-world Internet TLDs we accept for the plain "domain" pattern (keeps out most Java/Kotlin
// fully-qualified class names, which look exactly like reversed domains, e.g. "com.example.app.MainActivity").
const REAL_TLD = new Set(['com','org','net','io','co','dev','app','ai','me','info','biz','xyz','online','site','tech',
  'store','cloud','live','click','top','link','work','email','agency','news','games','page','pro','name','mobi',
  'tv','cc','gov','edu','int','mil','asia','in','us','uk','de','cn','jp','ru','br','au','ca','fr','es','it','nl',
  'se','no','fi','dk','pl','ch','at','be','nz','za','kr','mx','sg','hk','tw','id','th','vn','ph','my','pk','bd',
  'ir','sa','ae','tr','gr','pt','ie','il','eg','ng','ke','ua','cz','ro','hu','bg','rs','sk','hr','lt','lv','ee',
  'is','li','lu','mt','cy','al','ba','md','by','kz','uz','ar','cl','co_','pe','uy','ve','ec','bo','py','cr','pa',
  'do','gt','hn','sv','ni','jm','tt','bb','io_']);
// Reversed-package-name prefixes that are almost always Java/Kotlin fully-qualified class names, not domains.
const PKG_PREFIX = /^(android|androidx|java|javax|kotlin|kotlinx|rx|dagger|butterknife|okhttp3|retrofit2|com\.google|com\.android|com\.facebook|com\.squareup|com\.bumptech|com\.jakewharton|com\.github|org\.apache|org\.json|org\.junit|org\.jetbrains|io\.reactivex|io\.flutter|io\.grpc|com\.example)\./;

class Findings {
  constructor() { this.urls = new Map(); this.domains = new Map(); this.ips = new Map(); this.emails = new Map(); this.base64 = new Map(); this.secrets = []; this.pem = new Map(); }
  add(map, key, file) { if (!map.has(key)) { if (map.size >= MAX_FINDINGS_PER_KIND) return; map.set(key, new Set()); } map.get(key).add(file); }
  out(map) { return [...map.entries()].map(([value, files]) => ({ value, files: [...files].slice(0, 5), file_count: files.size })).sort((a, b) => b.file_count - a.file_count); }
}

function scanBuffer(buf, filename, f) {
  const slice = buf.length > MAX_FILE_SCAN ? buf.subarray(0, MAX_FILE_SCAN) : buf;
  const text = extractAsciiStrings(slice).join('\n') + '\n' + extractUtf16Strings(slice).join('\n');
  for (const m of text.matchAll(RE.url)) { const u = m[0].replace(/[),.;'"]+$/, ''); try { const h = new URL(u).hostname.toLowerCase(); if (!SCHEMA_HOSTS.has(h)) f.add(f.urls, u, filename); } catch { /* skip */ } }
  for (const m of text.matchAll(RE.domain)) { const d = m[0].toLowerCase(); const tld = d.slice(d.lastIndexOf('.') + 1); if (SKIP_DOMAIN_SUFFIX.test(d) || SCHEMA_HOSTS.has(d) || !d.includes('.') || /^\d+\.\d+$/.test(d) || !REAL_TLD.has(tld) || PKG_PREFIX.test(d)) continue; f.add(f.domains, d, filename); }
  for (const m of text.matchAll(RE.ipv4)) { if (!isPrivateIp(m[0])) f.add(f.ips, m[0], filename); }
  for (const m of text.matchAll(RE.email)) f.add(f.emails, m[0].toLowerCase(), filename);
  for (const m of text.matchAll(RE.jwt)) f.secrets.push({ severity: 'High', label: 'JWT token found in app', match: m[0].slice(0, 60) + '…', file: filename });
  for (const [re, sev, label] of SECRET_PATTERNS) for (const m of text.matchAll(re)) f.secrets.push({ severity: sev, label, match: (m[1] || m[0]).replace(/.(?=.{4})/g, '•'), file: filename });
  for (const m of text.matchAll(RE.pem)) f.pem.set(m[0].slice(0, 40), (f.pem.get(m[0].slice(0, 40)) || new Set()).add(filename));
  let n = 0;
  for (const m of text.matchAll(RE.base64)) {
    if (n++ > 4000) break; const s = m[0]; if (s.length < 24 || s.length > 4000 || !B64_PLAUSIBLE.test(s)) continue;
    const ent = shannonEntropy(s);
    if (ent > 4.3 && looksLikeKeyMaterial(s)) { f.add(f.base64, s.length > 80 ? s.slice(0, 80) + '…' : s, filename); if (ent > 5.3 && s.length > 200) f.secrets.push({ severity: 'Medium', label: 'High-entropy embedded blob (possible key/cert material)', match: s.slice(0, 40) + '…', file: filename }); }
  }
}

function permissionInfo(name) {
  const DANGEROUS = { 'android.permission.READ_SMS': 'Reads SMS messages', 'android.permission.SEND_SMS': 'Sends SMS (can cost money)', 'android.permission.RECEIVE_SMS': 'Receives SMS', 'android.permission.CAMERA': 'Uses the camera', 'android.permission.RECORD_AUDIO': 'Records audio/microphone', 'android.permission.ACCESS_FINE_LOCATION': 'Precise location', 'android.permission.ACCESS_COARSE_LOCATION': 'Approximate location', 'android.permission.READ_CONTACTS': 'Reads contacts', 'android.permission.WRITE_CONTACTS': 'Writes contacts', 'android.permission.READ_CALL_LOG': 'Reads call history', 'android.permission.READ_PHONE_STATE': 'Reads phone/IMEI state', 'android.permission.CALL_PHONE': 'Can place phone calls', 'android.permission.WRITE_EXTERNAL_STORAGE': 'Writes to shared storage', 'android.permission.READ_EXTERNAL_STORAGE': 'Reads shared storage', 'android.permission.SYSTEM_ALERT_WINDOW': 'Draws over other apps', 'android.permission.READ_CALENDAR': 'Reads calendar', 'android.permission.WRITE_CALENDAR': 'Writes calendar', 'android.permission.BLUETOOTH_CONNECT': 'Connects to Bluetooth devices', 'android.permission.ACCESS_BACKGROUND_LOCATION': 'Location in the background' };
  return DANGEROUS[name] || null;
}

function certInfo(zip) {
  const entry = zip.getEntries().find((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.entryName));
  if (!entry) return { present: false };
  try {
    const asn1 = forge.asn1.fromDer(forge.util.createBuffer(entry.getData().toString('binary')));
    const p7 = forge.pkcs7.messageFromAsn1(asn1); const cert = p7.certificates[0]; if (!cert) return { present: false };
    const subj = (f) => (cert.subject.getField(f) || {}).value || '';
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const sha1 = forge.md.sha1.create(); sha1.update(der);
    const sha256 = forge.md.sha256.create(); sha256.update(der);
    const isDebug = subj('CN') === 'Android Debug' && subj('O') === 'Android';
    const now = new Date();
    return { present: true, subject: cert.subject.attributes.map((a) => `${a.shortName}=${a.value}`).join(', '), issuer: cert.issuer.attributes.map((a) => `${a.shortName}=${a.value}`).join(', '), validFrom: cert.validity.notBefore, validTo: cert.validity.notAfter, expired: cert.validity.notAfter < now, serialNumber: cert.serialNumber, sha1: sha1.digest().toHex(), sha256: sha256.digest().toHex(), isDebugCert: isDebug };
  } catch { return { present: true, error: 'Could not parse the signing certificate (unsupported format).' }; }
}

function vulnChecks(manifest, cert, totalSize) {
  const v = []; const add = (severity, title, detail, fix) => v.push({ severity, title, detail, fix });
  const app = manifest.application || {};
  if (app.debuggable === true) add('Critical', 'App is debuggable', 'android:debuggable="true" lets anyone attach a debugger to your app on a real device and read its memory, including secrets and session tokens.', 'Remove android:debuggable or make sure your release build sets debuggable="false" (the default Android Gradle release build already does this — check you are not overriding it).');
  if (cert.present && cert.isDebugCert) add('Critical', 'Signed with the Android debug certificate', 'This build is signed with the default debug keystore (CN=Android Debug), not a real release key. It must never be distributed to real users — anyone can resign a modified copy with the same well-known debug key.', 'Build and sign a release APK/AAB with your own private keystore before distributing it.');
  if (cert.present && cert.expired) add('High', 'Signing certificate has expired', `The certificate used to sign this APK expired on ${new Date(cert.validTo).toDateString()}.`, 'Google Play requires the signing certificate to still be valid. Generate a new key if needed and consider Play App Signing.');
  if (app.allowBackup !== false) add('Medium', 'Full backup is allowed', 'android:allowBackup is not explicitly set to false, so on many devices "adb backup" can copy the app\u2019s private data (including local databases and shared preferences) without root.', 'Add android:allowBackup="false" in the <application> tag, or configure a proper android:fullBackupContent policy that excludes sensitive files.');
  if (app.usesCleartextTraffic === true) add('High', 'Cleartext (unencrypted HTTP) traffic is explicitly allowed', 'android:usesCleartextTraffic="true" lets the app send plain HTTP traffic that can be read or modified by anyone on the same network.', 'Set usesCleartextTraffic="false" and, from Android 7+, add a Network Security Config that blocks cleartext by default, allowing only domains that truly need it.');
  else if (app.usesCleartextTraffic !== false && manifest.usesSdk && manifest.usesSdk.targetSdkVersion && +manifest.usesSdk.targetSdkVersion < 28) add('Low', 'Cleartext traffic not explicitly disabled', 'Before targetSdkVersion 28, cleartext HTTP is allowed by default unless disabled.', 'Add a Network Security Config and set usesCleartextTraffic="false" to be explicit.');
  const sdk = manifest.usesSdk || {};
  if (sdk.minSdkVersion && +sdk.minSdkVersion < 21) add('Low', 'Very old minimum Android version supported', `minSdkVersion=${sdk.minSdkVersion} means the app can still run on very old, unpatched Android versions with known OS-level vulnerabilities.`, 'Consider raising minSdkVersion so users stay on OS versions still receiving security patches.');
  if (sdk.targetSdkVersion && +sdk.targetSdkVersion < 31) add('Medium', 'Outdated targetSdkVersion', `targetSdkVersion=${sdk.targetSdkVersion} is old enough that Google Play may already be blocking new updates, and the app misses newer OS security protections.`, 'Rebuild against a current targetSdkVersion and test for behaviour changes.');
  const comp = (list, kind) => (list || []).forEach((c) => { const hasFilter = (c.intentFilters || []).length > 0; const exported = c.exported === true || (c.exported === undefined && hasFilter); if (exported && !c.permission) add('Medium', `Exported ${kind} without a permission check`, `"${c.name}" is reachable by other apps on the device (exported${c.exported === undefined ? ', implicitly because it declares an intent-filter' : '="true"'}) and defines no android:permission, so any installed app can try to interact with it.`, `Add android:exported="false" if this ${kind} is only used internally, or require a signature-level android:permission if other apps should call it.`); });
  comp(app.activities, 'activity'); comp(app.services, 'service'); comp(app.receivers, 'broadcast receiver');
  (app.providers || []).forEach((p) => { if ((p.exported === true || p.exported === undefined) && !p.permission && !p.readPermission && !p.writePermission) add('High', 'Exported content provider without a permission check', `Content provider "${p.name}" is exported with no permission, so other apps may be able to query or modify its data.`, 'Add android:exported="false" if not needed externally, or set android:permission/readPermission/writePermission.'); });
  if (totalSize > 149 * 1024 * 1024) add('Low', 'APK is close to the 150 MB scan limit', 'Only the first part of very large files inside this APK may have been scanned for strings.', 'For a complete scan, consider sharing just the app module or the parts you are concerned about.');
  return v;
}

async function analyzeApk(buffer) {
  const zip = new AdmZip(buffer);
  const entries = zip.getEntries().filter((e) => !e.isDirectory);
  let manifest = null, manifestError = null;
  try { manifest = new (require('node-apk-parser/lib/apkreader/parser/manifest'))(zip.getEntry('AndroidManifest.xml').getData()).parse(); }
  catch (e) { manifestError = 'Could not parse AndroidManifest.xml (' + e.message.slice(0, 120) + ')'; }
  const cert = certInfo(zip);
  const f = new Findings(); let scanned = 0, filesScanned = 0;
  for (const e of entries) {
    if (scanned >= MAX_TOTAL_SCAN) break;
    const data = e.getData(); scanBuffer(data, e.entryName, f); scanned += Math.min(data.length, MAX_FILE_SCAN); filesScanned++;
  }
  const perms = manifest ? manifest.usesPermissions.map((p) => ({ name: p.name, risk: permissionInfo(p.name) })) : [];
  const dangerousPerms = perms.filter((p) => p.risk);
  return {
    meta: { fileCount: entries.length, filesScanned, totalUncompressedBytes: entries.reduce((s, e) => s + e.header.size, 0), sizeCappedScan: scanned >= MAX_TOTAL_SCAN },
    manifest: manifest ? { package: manifest.package, versionCode: manifest.versionCode, versionName: manifest.versionName, minSdk: manifest.usesSdk && manifest.usesSdk.minSdkVersion, targetSdk: manifest.usesSdk && manifest.usesSdk.targetSdkVersion, debuggable: !!(manifest.application && manifest.application.debuggable), allowBackup: manifest.application ? manifest.application.allowBackup !== false : null, usesCleartextTraffic: manifest.application ? manifest.application.usesCleartextTraffic : null, label: manifest.application && manifest.application.label, activityCount: manifest.application ? manifest.application.activities.length : 0, serviceCount: manifest.application ? manifest.application.services.length : 0, receiverCount: manifest.application ? manifest.application.receivers.length : 0, providerCount: manifest.application ? manifest.application.providers.length : 0 } : null,
    manifestError,
    permissions: perms, dangerousPermissions: dangerousPerms,
    certificate: cert,
    urls: f.out(f.urls), domains: f.out(f.domains), ips: f.out(f.ips), emails: f.out(f.emails), base64Blobs: f.out(f.base64),
    secrets: (() => { const seen = new Set(); return f.secrets.filter((x) => { const k = x.match + '|' + x.file; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 300); })(),
    vulnerabilities: manifest ? vulnChecks(manifest, cert, buffer.length) : [],
  };
}
module.exports = { analyzeApk, extractAsciiStrings, extractUtf16Strings, shannonEntropy, isPrivateIp };

// ---------- scoring ----------
function securityScore(vulns, secrets) {
  const w = { Critical: 30, High: 15, Medium: 7, Low: 2 };
  let deduct = 0;
  for (const v of vulns) deduct += w[v.severity] || 2;
  for (const s of secrets) deduct += (w[s.severity] || 2) * 0.6;
  return Math.max(0, Math.round(100 - deduct));
}
function grade(score) { return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F'; }

// ---------- diff between two analyses (e.g. two app versions) ----------
function diffSets(a, b) {
  const av = new Set(a.map((x) => x.value)), bv = new Set(b.map((x) => x.value));
  return { added: [...bv].filter((x) => !av.has(x)), removed: [...av].filter((x) => !bv.has(x)) };
}
function diffAnalyses(a, b) {
  return {
    versionA: a.manifest && { versionName: a.manifest.versionName, versionCode: a.manifest.versionCode },
    versionB: b.manifest && { versionName: b.manifest.versionName, versionCode: b.manifest.versionCode },
    domains: diffSets(a.domains, b.domains),
    urls: diffSets(a.urls, b.urls),
    permissions: diffSets(a.permissions.map((p) => ({ value: p.name })), b.permissions.map((p) => ({ value: p.name }))),
    newVulnerabilities: b.vulnerabilities.filter((v) => !a.vulnerabilities.some((x) => x.title === v.title)).map((v) => v.title),
    fixedVulnerabilities: a.vulnerabilities.filter((v) => !b.vulnerabilities.some((x) => x.title === v.title)).map((v) => v.title),
    scoreA: securityScore(a.vulnerabilities, a.secrets), scoreB: securityScore(b.vulnerabilities, b.secrets),
  };
}
module.exports.securityScore = securityScore;
module.exports.grade = grade;
module.exports.diffAnalyses = diffAnalyses;
