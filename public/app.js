'use strict';
const $ = (s, r = document) => r.querySelector(s);
const h = (t, a, ...k) => { const e = document.createElement(t); for (const [x, v] of Object.entries(a || {})) { if (x === 'class') e.className = v; else if (x.startsWith('on')) e[x] = v; else if (v !== false && v != null) e.setAttribute(x, v); } for (const c of k.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c))); return e; };
const app = $('#app');
const fmtMB = (b) => (b / 1024 / 1024).toFixed(2) + ' MB';
const sev = (s) => h('span', { class: 'badge sev-' + s }, s);
const say = (m, t, ok) => { m.textContent = t; m.className = 'msg ' + (ok ? 'ok' : 'bad'); };

const TERMS_TEXT = [
  ['What this tool does', 'APK Analyzer by Abhigyan ("the Tool") unzips an Android .apk file you upload and automatically looks for: app metadata, permissions, the signing certificate, and any domains, URLs, IP addresses, emails, and text that looks like an API key, token, password or private key anywhere inside the file. It also runs a small set of automated Android security checks (such as android:debuggable, android:allowBackup, cleartext traffic, and exported components) and produces a plain-language report with a security score.'],
  ['You must be authorized', 'You confirm that you own the application you upload, or that you have the legal right and explicit permission (for example as an employee, contractor, or authorized security researcher) to analyze it. Analyzing, reverse engineering, or probing software you are not authorized to test may be a criminal offense under applicable law, including but not limited to the Indian Information Technology Act, 2000 (notably sections 43 and 66, dealing with unauthorized access to computer systems and data), the Indian Penal Code / Bharatiya Nyaya Sanhita provisions on cheating and forgery where applicable, the United States Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act 1990, the EU/UK General Data Protection Regulation where personal data is involved, and equivalent computer-misuse and data-protection laws in other countries. You alone are responsible for ensuring you have the right to analyze the file you upload, and for how you use the results.'],
  ['No warranty, automated results only', 'This Tool performs automated pattern matching. A domain, URL, string, or "possible secret" appearing in a report is a lead for you to manually verify — it is not proof of an actual vulnerability, and the absence of a finding is not proof of safety. The security score is a rough, automated indicator only. The Tool is provided "AS IS" and "AS AVAILABLE", without warranties of any kind, express or implied, including fitness for a particular purpose, accuracy, or completeness.'],
  ['Limitation of liability', 'To the maximum extent permitted by applicable law, the creator of this Tool (Abhigyan) shall not be liable for any direct, indirect, incidental, special, consequential, or exemplary damages, including but not limited to loss of data, loss of profits, business interruption, or any damages arising from your use or inability to use the Tool, from reliance on its output, or from any unauthorized or illegal use of the Tool by you or anyone else. You agree to indemnify and hold harmless the creator from any claim, demand, loss, or damage arising out of your breach of these Terms or your violation of any law or third party right.'],
  ['Files are not stored', 'Uploaded files are processed in server memory only, for the sole purpose of generating your report, and are discarded immediately after the response is sent. The Tool does not require an account, does not use tracking cookies, and does not knowingly retain your file or the contents of your report after your session ends. Short-lived technical logs (such as IP-based rate limiting to prevent abuse) may be kept briefly and are deleted automatically.'],
  ['Optional live checks', 'If you tick the optional box to test whether a discovered Firebase Realtime Database URL is publicly readable, the Tool will send a single anonymous, read-only HTTP request to that address from its own server. Only use this on databases you are authorized to test; this is still your responsibility under the "You must be authorized" section above.'],
  ['Prohibited use', 'You may not use the Tool to facilitate attacks on third parties, to analyze malware for the purpose of redistributing it, to harvest and misuse secrets belonging to others, to upload content that is illegal in your jurisdiction, or to try to overload, scrape, or abuse the service.'],
  ['License', 'This report and the Tool\u2019s output are provided for your own legitimate security research and remediation purposes. You retain all rights to your own application and its contents. The Tool itself, its branding ("APK Analyzer by Abhigyan"), and its source code remain the property of its creator unless otherwise licensed separately.'],
  ['Governing law', 'These Terms are governed by the laws of India, without prejudice to any mandatory consumer-protection or data-protection law of your own country that may also apply to you. Any dispute shall be subject to the exclusive jurisdiction of the courts of India, to the extent permitted by law.'],
  ['Changes', 'These Terms may be updated at any time. Continuing to use the Tool after a change means you accept the updated Terms. Last updated: November 2026.'],
];

function termsGate(onAccept) {
  const box = h('div', { id: 'terms' }, h('h2', { style: 'margin-top:0' }, 'Terms of Use & License'), ...TERMS_TEXT.flatMap(([t, b]) => [h('h3', {}, t), h('p', { class: 'mut' }, b)]));
  const btn = h('button', { disabled: '' }, 'Scroll to the bottom to continue');
  btn.onclick = () => { sessionStorage.setItem('apk_terms_ok', '1'); onAccept(); };
  box.onscroll = () => { if (box.scrollTop + box.clientHeight >= box.scrollHeight - 12) { btn.removeAttribute('disabled'); btn.textContent = 'I have read and accept the Terms & License — Continue'; } };
  app.replaceChildren(h('h1', {}, 'Before you start'), h('p', { class: 'mut' }, 'Please read the full Terms. The button below unlocks once you reach the end.'), box, h('div', { style: 'margin-top:14px' }, btn));
}

function sevWeight(s) { return { Critical: 0, High: 1, Medium: 2, Low: 3 }[s] ?? 4; }
function scoreColor(s) { return s >= 75 ? 'var(--ok)' : s >= 45 ? 'var(--warn)' : 'var(--bad)'; }

function searchableTable(title, rows, cols) {
  if (!rows.length) return null;
  const q = h('input', { type: 'search', placeholder: 'Search ' + rows.length + ' ' + title.toLowerCase() + '…' });
  const tbl = h('table'), head = h('tr', {}, ...cols.map((c) => h('th', {}, c[0])));
  const draw = () => { const f = q.value.toLowerCase(); tbl.replaceChildren(head, ...rows.filter((r) => !f || cols.some((c) => String(c[1](r)).toLowerCase().includes(f))).slice(0, 500).map((r) => h('tr', {}, ...cols.map((c) => h('td', { class: c[2] || '' }, c[1](r)))))); };
  q.oninput = draw; draw();
  return h('div', { class: 'panel' }, h('b', {}, title + ' (' + rows.length + ')'), q, tbl);
}

function report(data, fileA, fileB) {
  const r = data.result, meta = data.meta;
  const vulns = [...r.vulnerabilities].sort((a, b) => sevWeight(a.severity) - sevWeight(b.severity));
  const secrets = [...r.secrets].sort((a, b) => sevWeight(a.severity) - sevWeight(b.severity));
  const scoreBox = h('div', { class: 'panel', style: 'text-align:center' }, h('div', { class: 'score', style: 'color:' + scoreColor(r.score) }, r.score + '/100'), h('div', { class: 'mut' }, 'Security score — Grade ' + r.grade), h('p', { class: 'mut', style: 'max-width:60ch;margin:8px auto 0' }, 'Automated and approximate. Treat every finding below as a lead to verify, not final proof.'));
  const mPanel = r.manifest ? h('div', { class: 'panel' }, h('b', {}, 'App details'), h('table', {},
    h('tr', {}, h('td', {}, 'Package'), h('td', { class: 'mono' }, r.manifest.package)),
    h('tr', {}, h('td', {}, 'Version'), h('td', {}, r.manifest.versionName + ' (code ' + r.manifest.versionCode + ')')),
    h('tr', {}, h('td', {}, 'Min / Target SDK'), h('td', {}, (r.manifest.minSdk || '—') + ' / ' + (r.manifest.targetSdk || '—'))),
    h('tr', {}, h('td', {}, 'Debuggable'), h('td', {}, r.manifest.debuggable ? sev('Critical') : 'No')),
    h('tr', {}, h('td', {}, 'Allows backup'), h('td', {}, r.manifest.allowBackup ? sev('Medium') : 'No')),
    h('tr', {}, h('td', {}, 'Components'), h('td', {}, `${r.manifest.activityCount} activities, ${r.manifest.serviceCount} services, ${r.manifest.receiverCount} receivers, ${r.manifest.providerCount} providers`)))) : h('div', { class: 'panel' }, r.manifestError || 'Manifest could not be read.');
  const cert = r.certificate;
  const cPanel = cert.present ? h('div', { class: 'panel' }, h('b', {}, 'Signing certificate'), cert.isDebugCert && h('p', {}, sev('Critical'), ' Signed with the default Android debug certificate — never distribute this build.'), h('table', {},
    h('tr', {}, h('td', {}, 'Subject'), h('td', { class: 'mono' }, cert.subject || '—')),
    h('tr', {}, h('td', {}, 'Valid'), h('td', {}, cert.validFrom ? new Date(cert.validFrom).toDateString() + ' → ' + new Date(cert.validTo).toDateString() + (cert.expired ? '  (EXPIRED)' : '') : '—')),
    h('tr', {}, h('td', {}, 'SHA-256'), h('td', { class: 'mono' }, cert.sha256 || '—')))) : h('div', { class: 'panel' }, 'No signing certificate found.');
  const permRows = r.dangerousPermissions.length ? h('div', { class: 'panel' }, h('b', {}, 'Notable permissions (' + r.dangerousPermissions.length + ' of ' + r.permissions.length + ' total)'), h('table', {}, ...r.dangerousPermissions.map((p) => h('tr', {}, h('td', { class: 'mono' }, p.name.replace('android.permission.', '')), h('td', { class: 'mut' }, p.risk))))) : null;
  const vulnBox = h('div', { class: 'panel' }, h('b', {}, 'Security findings (' + vulns.length + ')'), ...(vulns.length ? vulns.map((v) => h('div', { style: 'margin:12px 0;padding-top:10px;border-top:1px solid var(--line)' }, h('div', { class: 'row' }, sev(v.severity), h('b', {}, v.title)), h('p', { class: 'mut' }, v.detail), h('p', {}, h('b', {}, 'Fix: '), v.fix))) : [h('p', { class: 'mut' }, 'No automated checks were triggered.')]));
  const secretsBox = secrets.length ? h('div', { class: 'panel' }, h('b', {}, 'Possible secrets found (' + secrets.length + ')'), h('p', { class: 'mut' }, 'Values are partly masked. If any of these are real and still active, rotate them immediately.'), h('table', {}, ...secrets.map((s) => h('tr', {}, h('td', {}, sev(s.severity)), h('td', {}, s.label), h('td', { class: 'mono' }, s.match), h('td', { class: 'mut' }, s.file))))) : null;
  const fbRows = r.domains.filter((d) => /\.firebaseio\.com$/i.test(d.value));
  const fbBox = fbRows.length ? h('div', { class: 'panel' }, h('b', {}, 'Firebase Realtime Database found'), h('p', { class: 'mut' }, 'Optional: send one anonymous read-only request per database to see if it is publicly readable. Only do this for databases you are authorized to test.'), ...fbRows.map((d) => { const m = h('div', { class: 'msg' }); const btn = h('button', { class: 'alt', onclick: async () => { btn.disabled = true; say(m, 'Checking…', 1); try { const r2 = await (await fetch('/api/check-firebase', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://' + d.value }) })).json(); if (r2.error) say(m, r2.error); else say(m, (r2.publiclyReadable ? '⚠️ Publicly readable — fix your rules now. ' : '✔ Not publicly readable. ') + r2.note, !r2.publiclyReadable); } catch { say(m, 'Could not run the check.'); } btn.disabled = false; } }, 'Check ' + d.value); return h('div', { style: 'margin:8px 0' }, btn, m); })) : null;
  const domTable = searchableTable('Domains', r.domains, [['Domain', (x) => x.value, 'mono'], ['Seen in', (x) => x.file_count + ' file(s)']]);
  const urlTable = searchableTable('URLs', r.urls, [['URL', (x) => x.value, 'mono']]);
  const ipTable = searchableTable('IP addresses', r.ips, [['IP', (x) => x.value, 'mono']]);
  const emailTable = searchableTable('Emails', r.emails, [['Email', (x) => x.value, 'mono']]);
  const b64Table = searchableTable('Encoded / Base64-looking blobs', r.base64Blobs, [['Value', (x) => x.value, 'mono']]);
  const downloads = h('div', { class: 'panel row' },
    h('button', { onclick: async () => { const r2 = await fetch('/api/report.pdf', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(data) }); if (!r2.ok) return alert('Could not build the PDF.'); const blob = await r2.blob(); const a = h('a', { href: URL.createObjectURL(blob), download: 'apk-security-report.pdf' }); document.body.append(a); a.click(); a.remove(); } }, 'Download PDF'),
    h('button', { class: 'alt', onclick: () => { const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }); const a = h('a', { href: URL.createObjectURL(blob), download: 'apk-security-report.json' }); document.body.append(a); a.click(); a.remove(); } }, 'Download JSON'));
  app.replaceChildren(h('a', { href: '#/' }, '← Analyze another APK'), h('h1', {}, meta.filename), h('p', { class: 'mut' }, fmtMB(meta.size) + ' · ' + r.meta.filesScanned + ' files scanned' + (r.meta.sizeCappedScan ? ' (large file: scan was capped for speed)' : '')),
    scoreBox, downloads, mPanel, cPanel, permRows, vulnBox, secretsBox, fbBox, domTable, urlTable, ipTable, emailTable, b64Table);
}

function uploadPage() {
  const fileInput = h('input', { type: 'file', accept: '.apk,.xapk', class: 'hide' });
  const picked = h('div', { class: 'mut' }, 'No file chosen');
  const confirmBox = h('input', { type: 'checkbox', id: 'authck' });
  const msg = h('div', { class: 'msg' }), bar = h('progress', { value: '0', max: '100', class: 'hide' });
  const drop = h('div', { class: 'drop' }, h('p', {}, h('b', {}, 'Tap to choose an .apk file'), ' or drop it here'), h('p', { class: 'mut' }, 'Up to 150 MB. Processed in memory and deleted right after your report is generated.'));
  drop.onclick = () => fileInput.click();
  ['dragover', 'dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.toggle('over', ev === 'dragover'); if (ev === 'drop' && e.dataTransfer.files[0]) { fileInput.files = e.dataTransfer.files; fileInput.onchange(); } }));
  fileInput.onchange = () => { const f = fileInput.files[0]; picked.textContent = f ? f.name + ' — ' + fmtMB(f.size) : 'No file chosen'; };
  const btn = h('button', { disabled: '' }, 'Analyze APK');
  const upd = () => { btn.disabled = !(fileInput.files[0] && confirmBox.checked); };
  fileInput.addEventListener('change', upd); confirmBox.addEventListener('change', upd);
  btn.onclick = async () => {
    const f = fileInput.files[0]; if (!f) return;
    btn.disabled = true; bar.classList.remove('hide'); bar.removeAttribute('value'); say(msg, 'Uploading and scanning… this can take a little while for large files.', 1);
    try {
      const fd = new FormData(); fd.append('apk', f);
      const xhr = new XMLHttpRequest();
      const result = await new Promise((resolve, reject) => {
        xhr.open('POST', '/api/analyze'); xhr.responseType = 'json';
        xhr.upload.onprogress = (e) => { if (e.lengthComputable) bar.value = Math.round((e.loaded / e.total) * 100); };
        xhr.onload = () => (xhr.status === 200 ? resolve(xhr.response) : reject(new Error((xhr.response && xhr.response.error) || 'Request failed')));
        xhr.onerror = () => reject(new Error('Network error.'));
        xhr.send(fd);
      });
      report(result);
    } catch (e) { say(msg, e.message); bar.classList.add('hide'); btn.disabled = false; }
  };
  app.replaceChildren(h('h1', {}, 'Find what is hiding inside your APK'), h('p', { class: 'mut' }, 'Every domain, URL, API key and dangerous setting — found automatically, explained in plain language, with a security score and exact fixes.'),
    h('div', { class: 'panel' }, drop, fileInput, picked, h('label', { style: 'display:block;margin-top:12px' }, confirmBox, ' I confirm this APK is mine, or I am authorized to analyze it.'), h('div', { style: 'margin-top:12px' }, btn), bar, msg),
    h('div', { class: 'panel' }, h('b', {}, 'Compare two versions'), h('p', { class: 'mut' }, 'Upload an older and a newer build of the same app to see exactly what domains, permissions and issues changed.'), h('a', { class: 'btn alt', href: '#/diff' }, 'Compare two APKs')));
}

function diffPage() {
  const a = h('input', { type: 'file', accept: '.apk,.xapk' }), b = h('input', { type: 'file', accept: '.apk,.xapk' }), msg = h('div', { class: 'msg' }), out = h('div');
  const confirmBox = h('input', { type: 'checkbox' });
  const btn = h('button', { onclick: async () => {
    if (!a.files[0] || !b.files[0]) return say(msg, 'Choose both files.');
    if (!confirmBox.checked) return say(msg, 'Please confirm you are authorized to analyze both files.');
    btn.disabled = true; say(msg, 'Comparing…', 1);
    try {
      const fd = new FormData(); fd.append('apkA', a.files[0]); fd.append('apkB', b.files[0]);
      const r = await fetch('/api/diff', { method: 'POST', body: fd }); const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Failed.');
      say(msg, 'Done.', 1);
      const rows = (title, x) => h('div', { class: 'panel' }, h('b', {}, title), x.added.length ? h('p', {}, '+ Added: ', h('span', { class: 'mono' }, x.added.join(', '))) : null, x.removed.length ? h('p', {}, '− Removed: ', h('span', { class: 'mono' }, x.removed.join(', '))) : null, !x.added.length && !x.removed.length ? h('p', { class: 'mut' }, 'No change.') : null);
      out.replaceChildren(
        h('div', { class: 'panel row sp' }, h('div', {}, h('div', { class: 'mut' }, 'Version A'), h('b', {}, (d.versionA && d.versionA.versionName) || '—')), h('div', { style: 'font-size:1.4rem' }, '→'), h('div', {}, h('div', { class: 'mut' }, 'Version B'), h('b', {}, (d.versionB && d.versionB.versionName) || '—')), h('div', {}, h('div', { class: 'mut' }, 'Score'), h('b', {}, d.scoreA + ' → ' + d.scoreB))),
        rows('Domains', d.domains), rows('URLs', d.urls), rows('Permissions', d.permissions),
        d.newVulnerabilities.length ? h('div', { class: 'panel' }, h('b', {}, 'New issues in version B'), h('p', {}, d.newVulnerabilities.join(', '))) : null,
        d.fixedVulnerabilities.length ? h('div', { class: 'panel' }, h('b', {}, 'Fixed since version A'), h('p', {}, d.fixedVulnerabilities.join(', '))) : null);
    } catch (e) { say(msg, e.message); }
    btn.disabled = false;
  } }, 'Compare');
  app.replaceChildren(h('a', { href: '#/' }, '← Back'), h('h1', {}, 'Compare two APK versions'), h('div', { class: 'panel' }, h('label', {}, 'Older version (A)'), a, h('label', {}, 'Newer version (B)'), b, h('label', { style: 'display:block;margin-top:10px' }, confirmBox, ' I confirm I am authorized to analyze both files.'), h('div', { style: 'margin-top:10px' }, btn), msg), out);
}

function pageTerms() { app.replaceChildren(h('a', { href: '#/' }, '← Back'), h('h1', {}, 'Terms of Use & License'), ...TERMS_TEXT.flatMap(([t, b]) => [h('h2', {}, t), h('p', {}, b)])); }

function route() {
  window.scrollTo(0, 0);
  const r = location.hash.replace(/^#\/?/, '');
  if (r === 'p/terms') return pageTerms();
  if (sessionStorage.getItem('apk_terms_ok') !== '1') return termsGate(route);
  if (r === 'diff') return diffPage();
  return uploadPage();
}
addEventListener('hashchange', route); route();
