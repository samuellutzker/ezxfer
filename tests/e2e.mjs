// End-to-end browser tests (Playwright + Chromium).
// Usage: node tests/e2e.mjs ./ezxfer [--tls]
// With --tls the server runs with a self-signed certificate (HTTPS/WSS).
// Test-only dependencies: playwright, jsqr (cd tests && npm install).
import { spawn, execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const here = path.dirname(new URL(import.meta.url).pathname);
function load(name) {
  const tries = [createRequire(path.join(here, 'package.json'))];
  try { tries.push(createRequire(path.join(execSync('npm root -g').toString().trim(), 'noop.js'))); } catch {}
  if (process.env.NODE_PATH) for (const p of process.env.NODE_PATH.split(':')) tries.push(createRequire(path.join(p, 'noop.js')));
  for (const r of tries) { try { return { mod: r(name), file: r.resolve(name) }; } catch {} }
  return null;
}
const pw = load('playwright');
if (!pw) { console.log('playwright not installed - skipping e2e tests'); process.exit(0); }
const { chromium, devices } = pw.mod;
const jsqr = load('jsqr');

const BIN = path.resolve(process.argv[2] || './ezxfer');
const TLS = process.argv.includes('--tls');
const SCHEME = TLS ? 'https' : 'http';
const OUT = process.env.E2E_OUT || fs.mkdtempSync(path.join(os.tmpdir(), 'ezxfer-e2e-'));
const certArgs = [];
let spki = '';
if (TLS) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ezxfer-e2e-cert-'));
  execSync(`openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=ezxfer-e2e ` +
    `-keyout ${dir}/key.pem -out ${dir}/cert.pem`, { stdio: 'ignore' });
  certArgs.push('--cert', `${dir}/cert.pem`, '--key', `${dir}/key.pem`);
  // Make the browser trust this certificate, as a real setup would (e.g. mkcert):
  // Chrome only allows service workers on sites with a trusted certificate.
  spki = execSync(`openssl x509 -in ${dir}/cert.pem -pubkey -noout | openssl pkey -pubin -outform der | ` +
    'openssl dgst -sha256 -binary | openssl base64').toString().trim();
}
console.log(`mode: ${TLS ? 'HTTPS/WSS (self-signed certificate, trusted by the test browser)' : 'plain HTTP/WS'}`);
const sha = (b) => createHash('sha256').update(b).digest('hex');
let passed = 0;
function ok(name, extra = '') { passed++; console.log(`  ok  ${name}${extra ? '  ' + extra : ''}`); }
function assert(c, msg) { if (!c) throw new Error('assertion failed: ' + msg); }

const port = await new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
let server = spawn(BIN, ['-p', String(port), '--quiet', ...certArgs], { stdio: 'inherit' });
await new Promise((r) => setTimeout(r, 300));

// Talk to the server directly even if an HTTP(S)_PROXY is configured.
const browserEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/_proxy$/i.test(k)));
const browser = await chromium.launch({
  args: ['--no-proxy-server', ...(spki ? [`--ignore-certificate-errors-spki-list=${spki}`] : [])], env: browserEnv });
const errors = [];
function watch(page, label) {
  page.on('pageerror', (e) => errors.push(`${label}: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(`${label} console: ${m.text()}`); });
}

// Simulates the File System Access API save dialog, collecting written bytes.
const mockSavePicker = () => {
  window.__saved = {};
  window.showSaveFilePicker = async ({ suggestedName }) => ({
    createWritable: async () => {
      const parts = [];
      return {
        write: async (d) => { parts.push(new Uint8Array(d.buffer ? d.buffer.slice(d.byteOffset, d.byteOffset + d.byteLength) : d)); },
        close: async () => {
          const blob = new Blob(parts);
          const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
          window.__saved[suggestedName] = { size: blob.size, sha: [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('') };
        },
        abort: async () => { window.__saved[suggestedName] = 'aborted'; },
      };
    },
  });
};

// Records Screen Wake Lock requests/releases.
const mockWakeLock = () => {
  window.__wake = { log: [], held: false };
  Object.defineProperty(Navigator.prototype, 'wakeLock', { configurable: true, value: {
    request: async (type) => {
      const listeners = [];
      window.__wake.log.push('request:' + type); window.__wake.held = true;
      return {
        addEventListener: (ev, fn) => listeners.push(fn),
        release: async () => { window.__wake.log.push('release'); window.__wake.held = false; listeners.forEach((f) => f()); },
      };
    },
  } });
};

const row = (page, list, name) => page.locator(`#${list} .item`, { has: page.locator('.name', { hasText: name }) });

try {
  // ---------- desktop page creates a session and shows a QR code ----------
  const desk = await browser.newContext({ viewport: { width: 1280, height: 860 }, ignoreHTTPSErrors: true });
  await desk.addInitScript(mockSavePicker);
  await desk.addInitScript(mockWakeLock);
  const A = await desk.newPage(); watch(A, 'desktop');
  await A.goto(`${SCHEME}://127.0.0.1:${port}/`);
  await A.waitForFunction(() => window.ezxfer && window.ezxfer.session);
  const session = await A.evaluate(() => window.ezxfer.session);
  const joinUrl = await A.evaluate(() => window.ezxfer.url);
  await A.waitForFunction(() => { const i = document.getElementById('qr'); return i.complete && i.naturalWidth > 0; });
  assert((await A.textContent('#code')) === session, 'session code displayed');
  assert((await A.textContent('#pillText')) === 'Waiting for device', 'waiting pill');
  assert(new URL(A.url()).searchParams.get('s') === session, 'URL carries session for reloads');
  assert(joinUrl.startsWith(SCHEME + '://'), `join URL uses ${SCHEME}: ${joinUrl}`);
  assert(await A.evaluate(() => window.isSecureContext), 'secure context');
  ok('desktop shows session + QR', `session=${session}`);
  if (TLS) {
    // typing the address without https:// lands on the HTTPS page
    const R = await desk.newPage();
    await R.goto(`http://127.0.0.1:${port}/`);
    assert(R.url().startsWith(`https://127.0.0.1:${port}/`), `redirected: ${R.url()}`);
    await R.waitForFunction(() => window.ezxfer && window.ezxfer.session);
    await R.close();
    ok('http:// is redirected to https://');
  }

  // ---------- "scan" the QR code from the rendered image ----------
  let scanned = joinUrl;
  if (jsqr) {
    await A.addScriptTag({ path: jsqr.file });
    scanned = await A.evaluate(() => {
      const img = document.getElementById('qr');
      const c = document.createElement('canvas'); c.width = c.height = 400;
      const g = c.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, 400, 400); g.drawImage(img, 0, 0, 400, 400);
      const r = window.jsQR(g.getImageData(0, 0, 400, 400).data, 400, 400);
      return r && r.data;
    });
    assert(scanned === joinUrl, `QR decodes to join URL (${scanned} vs ${joinUrl})`);
    ok('QR code scans to the join URL', scanned);
  } else console.log('  --  jsqr not installed, skipping QR scan check');
  await A.screenshot({ path: path.join(OUT, 'desktop-waiting.png') });

  // ---------- phone joins by opening the scanned URL ----------
  const phoneCtx = await browser.newContext({ ...devices['iPhone 13'], acceptDownloads: true, ignoreHTTPSErrors: true });
  // Safari on iOS has no File System Access API (Chromium would expose it over HTTPS)
  await phoneCtx.addInitScript(() => { delete window.showSaveFilePicker; });
  // ...and older iOS versions have no Screen Wake Lock API
  await phoneCtx.addInitScript(() => { delete Navigator.prototype.wakeLock; });
  const B = await phoneCtx.newPage(); watch(B, 'phone');
  await B.goto(scanned);
  await A.waitForFunction(() => document.body.classList.contains('connected'));
  await B.waitForFunction(() => document.body.classList.contains('connected'));
  await A.waitForFunction(() => document.getElementById('peerName').textContent === 'iPhone');
  await B.waitForFunction(() => document.getElementById('peerName').textContent !== 'Device');
  assert(!(await B.evaluate(() => typeof window.showSaveFilePicker === 'function')), 'phone uses download fallback');
  ok('phone joins via QR URL; both sides connected', `phone sees "${await B.textContent('#peerName')}"`);

  // ---------- responsive layout ----------
  const overflow = await B.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  assert(overflow <= 0, `no horizontal overflow on phone (${overflow}px)`);
  const cols = await A.evaluate(() => getComputedStyle(document.querySelector('.grid')).gridTemplateColumns.split(' ').length);
  const phoneCols = await B.evaluate(() => getComputedStyle(document.querySelector('.grid')).gridTemplateColumns.split(' ').length);
  assert(cols === 2 && phoneCols === 1, `desktop 2 columns, phone 1 (${cols}/${phoneCols})`);
  ok('responsive layout (desktop 2 cols, phone 1 col, no overflow)');

  // ---------- desktop -> phone: offer appears, transfer starts on accept ----------
  const big = randomBytes(9 * 1024 * 1024 + 12345);
  await A.setInputFiles('#fileInput', [
    { name: 'holiday-video.mp4', mimeType: 'video/mp4', buffer: big },
    { name: 'empty.txt', mimeType: 'text/plain', buffer: Buffer.alloc(0) },
  ]);
  await row(B, 'inList', 'holiday-video.mp4').waitFor();
  await row(B, 'inList', 'empty.txt').waitFor();
  assert((await row(A, 'outList', 'holiday-video.mp4').locator('.status').textContent()).includes('Waiting for the other device'), 'sender waits for accept');
  await B.waitForFunction(() => !document.querySelector('.toast'));  // a clean screenshot for the README
  await B.screenshot({ path: path.join(OUT, 'phone-incoming.png') });
  ok('offers pop up on the peer before any data is sent');

  let t0 = Date.now();
  const [dl] = await Promise.all([B.waitForEvent('download'), row(B, 'inList', 'holiday-video.mp4').getByRole('button', { name: 'Accept' }).click()]);
  assert(dl.suggestedFilename() === 'holiday-video.mp4', 'download filename');
  const got = fs.readFileSync(await dl.path());
  assert(got.length === big.length && sha(got) === sha(big), 'downloaded bytes match');
  await row(A, 'outList', 'holiday-video.mp4').locator('.st-done').waitFor();
  await row(B, 'inList', 'holiday-video.mp4').locator('.st-done').waitFor();
  ok('desktop -> phone 9 MB transfer (download fallback), bytes identical', `${Date.now() - t0} ms`);

  // the sender held a screen wake lock while sending and let it go afterwards
  await A.waitForFunction(() => !window.__wake.held);
  const wake = await A.evaluate(() => window.__wake.log);
  assert(wake[0] === 'request:screen' && wake.includes('release'), 'wake lock log: ' + wake.join(','));
  // the phone (no wake lock API) is told to keep its screen on instead
  await B.locator('.toast', { hasText: 'Keep this screen on' }).waitFor();
  ok('screen wake lock held during the transfer (hint shown where unsupported)', wake.join(' → '));

  const [dl0] = await Promise.all([B.waitForEvent('download'), row(B, 'inList', 'empty.txt').getByRole('button', { name: 'Accept' }).click()]);
  assert(fs.readFileSync(await dl0.path()).length === 0, 'empty file');
  await row(A, 'outList', 'empty.txt').locator('.st-done').waitFor();
  ok('empty file transfer');

  // ---------- phone -> desktop with the save-file picker ----------
  const photo = randomBytes(3 * 1024 * 1024 + 7);
  await B.setInputFiles('#fileInput', { name: 'IMG_0042.HEIC', mimeType: 'image/heic', buffer: photo });
  await row(A, 'inList', 'IMG_0042.HEIC').waitFor();
  t0 = Date.now();
  await row(A, 'inList', 'IMG_0042.HEIC').getByRole('button', { name: 'Accept' }).click();
  await A.waitForFunction(() => window.__saved && window.__saved['IMG_0042.HEIC']);
  const saved = await A.evaluate(() => window.__saved['IMG_0042.HEIC']);
  assert(saved.size === photo.length && saved.sha === sha(photo), 'picker-saved bytes match');
  await row(B, 'outList', 'IMG_0042.HEIC').locator('.st-done').waitFor();
  ok('phone -> desktop 3 MB transfer (save-file picker), bytes identical', `${Date.now() - t0} ms`);

  // ---------- several files queued at once ----------
  const files = [1, 2, 3].map((i) => ({ name: `doc-${i}.pdf`, mimeType: 'application/pdf', buffer: randomBytes(400000 * i) }));
  await B.setInputFiles('#fileInput', files);
  for (const f of files) await row(A, 'inList', f.name).waitFor();
  for (const f of files) await row(A, 'inList', f.name).getByRole('button', { name: 'Accept' }).click();
  await A.waitForFunction(() => ['doc-1.pdf', 'doc-2.pdf', 'doc-3.pdf'].every((n) => window.__saved[n]));
  for (const f of files) {
    const s = await A.evaluate((n) => window.__saved[n], f.name);
    assert(s.sha === sha(f.buffer), `${f.name} matches`);
  }
  ok('three files accepted together arrive intact');

  // ---------- decline ----------
  await A.setInputFiles('#fileInput', { name: 'unwanted.zip', mimeType: 'application/zip', buffer: randomBytes(1000) });
  await row(B, 'inList', 'unwanted.zip').getByRole('button', { name: 'Decline' }).click();
  await row(A, 'outList', 'unwanted.zip').locator('.st-err', { hasText: 'Declined' }).waitFor();
  ok('decline is shown to the sender');

  // ---------- receiver cancels mid-transfer ----------
  const hugePath = path.join(OUT, 'huge.bin');
  fs.writeFileSync(hugePath, randomBytes(64 * 1024 * 1024));
  await A.setInputFiles('#fileInput', hugePath);
  await row(B, 'inList', 'huge.bin').getByRole('button', { name: 'Accept' }).click();
  await row(B, 'inList', 'huge.bin').getByRole('button', { name: 'Cancel' }).click({ timeout: 5000 });
  await row(A, 'outList', 'huge.bin').locator('.st-err', { hasText: 'Cancelled' }).waitFor();
  await row(B, 'inList', 'huge.bin').locator('.st-err', { hasText: 'Cancelled' }).waitFor();
  fs.unlinkSync(hugePath);
  ok('receiver cancels a running transfer; both sides show it');

  // ---------- sender cancels a pending offer ----------
  await A.setInputFiles('#fileInput', { name: 'oops.txt', mimeType: 'text/plain', buffer: Buffer.from('x') });
  await row(B, 'inList', 'oops.txt').waitFor();
  await row(A, 'outList', 'oops.txt').getByRole('button', { name: 'Cancel' }).click();
  await row(B, 'inList', 'oops.txt').locator('.st-err', { hasText: 'Cancelled' }).waitFor();
  ok('sender withdraws an offer; receiver sees it cancelled');

  // still healthy after cancellations
  const after = randomBytes(200000);
  await A.setInputFiles('#fileInput', { name: 'after.bin', mimeType: '', buffer: after });
  const [dl2] = await Promise.all([B.waitForEvent('download'), row(B, 'inList', 'after.bin').getByRole('button', { name: 'Accept' }).click()]);
  assert(sha(fs.readFileSync(await dl2.path())) === sha(after), 'post-cancel transfer intact');
  ok('connection keeps working after cancellations');

  // ---------- resume: receiving phone loses its network mid-transfer ----------
  const progress = (page, name) => page.evaluate((n) => (window.ezxfer.transfers().find((t) => t.name === n) || {}).bytes || 0, name);
  const bigPath = path.join(OUT, 'movie.mov');
  fs.writeFileSync(bigPath, randomBytes(80 * 1024 * 1024));
  const bigSha = sha(fs.readFileSync(bigPath));
  await A.setInputFiles('#fileInput', bigPath);
  const dlBig = B.waitForEvent('download', { timeout: 120000 });
  dlBig.catch(() => {});
  await row(B, 'inList', 'movie.mov').getByRole('button', { name: 'Accept' }).click();
  await B.waitForFunction(() => (window.ezxfer.transfers().find((t) => t.name === 'movie.mov') || {}).bytes > 20e6);
  await B.evaluate(() => window.ezxfer.dropConnection(true));  // vanishes without closing the socket
  const pausedAt = await progress(B, 'movie.mov');
  assert((await B.evaluate(() => window.ezxfer.transfers().find((t) => t.name === 'movie.mov').paused)), 'phone shows paused');
  const got80 = fs.readFileSync(await (await dlBig).path());
  assert(got80.length === 80 * 1024 * 1024 && sha(got80) === bigSha, 'resumed download identical');
  assert((await B.evaluate(() => window.ezxfer.resumes)) >= 1, 'phone resumed');
  await row(A, 'outList', 'movie.mov').locator('.st-done').waitFor();
  fs.unlinkSync(bigPath);
  ok('receiver drops mid-transfer, reconnects and resumes; bytes identical', `paused at ${(pausedAt / 1e6).toFixed(0)} MB`);

  // ---------- resume: sending phone's connection closes mid-transfer ----------
  const upPath = path.join(OUT, 'VID_0001.mp4');
  fs.writeFileSync(upPath, randomBytes(48 * 1024 * 1024));
  const upSha = sha(fs.readFileSync(upPath));
  await B.setInputFiles('#fileInput', upPath);
  await row(A, 'inList', 'VID_0001.mp4').getByRole('button', { name: 'Accept' }).click();
  await B.waitForFunction(() => (window.ezxfer.transfers().find((t) => t.name === 'VID_0001.mp4') || {}).bytes > 12e6);
  await B.evaluate(() => window.ezxfer.dropConnection(false));
  await A.waitForFunction(() => window.__saved && window.__saved['VID_0001.mp4'], null, { timeout: 120000 });
  const upSaved = await A.evaluate(() => window.__saved['VID_0001.mp4']);
  assert(upSaved.sha === upSha, 'resumed upload identical');
  assert((await A.evaluate(() => window.ezxfer.resumes)) >= 1, 'desktop resumed');
  await row(B, 'outList', 'VID_0001.mp4').locator('.st-done').waitFor();
  fs.unlinkSync(upPath);
  ok('sender drops mid-transfer, reconnects and resumes; bytes identical');

  // ---------- choosing files: a connection drop meanwhile is expected, not reported ----------
  const [chooser] = await Promise.all([B.waitForEvent('filechooser'), B.click('#drop')]);
  await A.waitForFunction(() => document.getElementById('pillText').textContent === 'Choosing files…');
  // Android drops the connection while its picker is open and can't reconnect
  // until the user is back: go offline, close the socket, wait a while.
  await phoneCtx.setOffline(true);
  await B.evaluate(() => window.ezxfer.dropConnection(false));
  await A.waitForFunction(() => !window.ezxfer.connected);
  await new Promise((r) => setTimeout(r, 3000));
  assert(await A.evaluate(() => document.body.classList.contains('connected')), 'stays on the transfer screen');
  assert((await A.textContent('#pillText')) === 'Choosing files…', 'pill says choosing files');
  assert((await A.locator('.toast', { hasText: 'disconnected' }).count()) === 0, 'no disconnect message');
  await phoneCtx.setOffline(false);
  const chosen = randomBytes(250000);
  await chooser.setFiles({ name: 'chosen.jpg', mimeType: 'image/jpeg', buffer: chosen });
  await row(A, 'inList', 'chosen.jpg').getByRole('button', { name: 'Accept' }).click();
  await A.waitForFunction(() => window.__saved['chosen.jpg']);
  assert((await A.evaluate(() => window.__saved['chosen.jpg'].sha)) === sha(chosen), 'chosen file intact');
  assert((await A.textContent('#pillText')) === 'Connected', 'pill back to connected');
  assert((await A.locator('.toast', { hasText: 'disconnected' }).count()) === 0, 'still no disconnect message');
  ok('connection lost while choosing files shows "Choosing files…", not a disconnect');

  // ...whereas losing the connection otherwise (e.g. app backgrounded) is reported
  await B.evaluate(() => window.ezxfer.dropConnection(false));
  await A.locator('.toast', { hasText: 'Device disconnected' }).waitFor({ timeout: 5000 });
  await B.waitForFunction(() => document.body.classList.contains('connected'));
  await A.waitForFunction(() => document.body.classList.contains('connected'));
  ok('connection lost otherwise is reported as a disconnect');

  // ---------- files picked while the connection is down are not lost ----------
  // (phones often lose the connection while their file picker is open)
  await B.evaluate(() => window.ezxfer.dropConnection(true));
  const picked = randomBytes(300000);
  await B.setInputFiles('#fileInput', { name: 'picked-offline.jpg', mimeType: 'image/jpeg', buffer: picked });
  await row(A, 'inList', 'picked-offline.jpg').getByRole('button', { name: 'Accept' }).click();
  await A.waitForFunction(() => window.__saved['picked-offline.jpg']);
  assert((await A.evaluate(() => window.__saved['picked-offline.jpg'].sha)) === sha(picked), 'offline pick intact');
  ok('files picked while disconnected are offered once the connection is back');

  // ---------- a connection that died silently is noticed on returning to the page ----------
  const conns = await B.evaluate(() => window.ezxfer.connections);
  await B.evaluate(() => window.ezxfer.freezeConnection());  // socket "open", nothing arrives
  t0 = Date.now();
  await B.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));  // back on the page
  await B.waitForFunction((n) => window.ezxfer.connections > n && document.body.classList.contains('connected'), conns,
    { timeout: 10000 });
  await A.waitForFunction(() => document.body.classList.contains('connected'));
  ok('dead connection detected on return and replaced', `${Date.now() - t0} ms`);

  // ---------- the phone reloads the page (as Android does to background tabs) ----------
  await B.reload();
  await B.waitForFunction(() => document.body.classList.contains('connected'));
  assert((await B.evaluate(() => window.ezxfer.session)) === session, 'same session after reload');
  const afterReload = randomBytes(200000);
  await B.setInputFiles('#fileInput', { name: 'after-reload.png', mimeType: 'image/png', buffer: afterReload });
  await row(A, 'inList', 'after-reload.png').getByRole('button', { name: 'Accept' }).click();
  await A.waitForFunction(() => window.__saved['after-reload.png']);
  assert((await A.evaluate(() => window.__saved['after-reload.png'].sha)) === sha(afterReload), 'post-reload file intact');
  ok('reloaded phone keeps its place in the session and can send again');

  // a transfer interrupted by a reload ends cleanly instead of waiting forever
  const relPath = path.join(OUT, 'interrupted.bin');
  fs.writeFileSync(relPath, randomBytes(64 * 1024 * 1024));
  await B.setInputFiles('#fileInput', relPath);
  await row(A, 'inList', 'interrupted.bin').getByRole('button', { name: 'Accept' }).click();
  await A.waitForFunction(() => (window.ezxfer.transfers().find((t) => t.name === 'interrupted.bin') || {}).bytes > 4e6);
  await B.reload();
  await row(A, 'inList', 'interrupted.bin').locator('.st-err').waitFor({ timeout: 15000 });
  await B.waitForFunction(() => document.body.classList.contains('connected'));
  fs.unlinkSync(relPath);
  ok('transfer interrupted by a reload ends with an error, not stuck paused',
     await row(A, 'inList', 'interrupted.bin').locator('.st-err').textContent());
  await A.screenshot({ path: path.join(OUT, 'desktop-transfers.png') });
  await B.screenshot({ path: path.join(OUT, 'phone-transfers.png'), fullPage: true });

  // ---------- phone leaves, then rejoins the same session ----------
  await B.close();
  await A.waitForFunction(() => !document.body.classList.contains('connected'));
  assert((await A.textContent('#pillText')) === 'Waiting for device', 'back to waiting');
  const B2 = await phoneCtx.newPage(); watch(B2, 'phone2');
  await B2.goto(scanned);
  await A.waitForFunction(() => document.body.classList.contains('connected'));
  ok('phone disconnect detected; same QR reconnects');
  await B2.close();
  await A.waitForFunction(() => !document.body.classList.contains('connected'));

  // ---------- Android phone: download streamed to disk via the service worker ----------
  // (the page is a secure context on 127.0.0.1 even over plain HTTP)
  const droidCtx = await browser.newContext({ ...devices['Pixel 7'], acceptDownloads: true, ignoreHTTPSErrors: true });
  await droidCtx.addInitScript(() => { delete window.showSaveFilePicker; });  // as on Android Chrome
  const P = await droidCtx.newPage(); watch(P, 'android');
  await P.goto(`${SCHEME}://127.0.0.1:${port}/?s=${session}`);
  await P.waitForFunction(() => document.body.classList.contains('connected'));
  await A.waitForFunction(() => document.getElementById('peerName').textContent === 'Android phone');
  const apkPath = path.join(OUT, 'app-release.apk');
  fs.writeFileSync(apkPath, randomBytes(40 * 1024 * 1024));
  const apkSha = sha(fs.readFileSync(apkPath));
  await A.setInputFiles('#fileInput', apkPath);
  const dlApk = P.waitForEvent('download', { timeout: 120000 });
  dlApk.catch(() => {});  // awaited below; don't crash the run if a step before fails
  await row(P, 'inList', 'app-release.apk').getByRole('button', { name: 'Accept' }).click();
  const apkInfo = () => P.evaluate(() => window.ezxfer.transfers().find((t) => t.name === 'app-release.apk') || {});
  await P.waitForFunction(() => (window.ezxfer.transfers().find((t) => t.name === 'app-release.apk') || {}).bytes > 10e6);
  assert((await apkInfo()).via === 'stream', 'android uses the streamed download: ' + (await apkInfo()).via);
  await P.evaluate(() => window.ezxfer.dropConnection(true));  // and survives a reconnect while streaming
  const apkDl = await dlApk;
  assert(apkDl.suggestedFilename() === 'app-release.apk', 'streamed filename ' + apkDl.suggestedFilename());
  const gotApk = fs.readFileSync(await apkDl.path());
  assert(gotApk.length === 40 * 1024 * 1024 && sha(gotApk) === apkSha, 'streamed download identical');
  await row(A, 'outList', 'app-release.apk').locator('.st-done').waitFor();
  const heap = await P.evaluate(() => performance.memory ? performance.memory.usedJSHeapSize : 0);
  fs.unlinkSync(apkPath);
  await droidCtx.close();
  await A.waitForFunction(() => !document.body.classList.contains('connected'));
  ok('android streams a 40 MB download to disk through the service worker, across a reconnect',
     heap ? `page JS heap ${(heap / 1e6).toFixed(0)} MB` : '');

  // ---------- another computer joins by typing the code ----------
  const other = await browser.newContext({ viewport: { width: 1000, height: 800 }, ignoreHTTPSErrors: true });
  const C = await other.newPage(); watch(C, 'computer2');
  await C.goto(`${SCHEME}://127.0.0.1:${port}/`);
  await C.waitForFunction(() => window.ezxfer.session);
  assert((await C.evaluate(() => window.ezxfer.session)) !== session, 'C got its own session');
  await C.fill('#joinCode', session.toLowerCase());
  await C.click('#joinForm button[type=submit]');
  await C.waitForFunction(() => document.body.classList.contains('connected'));
  await A.waitForFunction(() => document.body.classList.contains('connected'));
  assert((await C.evaluate(() => window.ezxfer.session)) === session, 'C joined A');
  const note = Buffer.from('typed-code transfer works');
  await C.setInputFiles('#fileInput', { name: 'note.txt', mimeType: 'text/plain', buffer: note });
  await row(A, 'inList', 'note.txt').getByRole('button', { name: 'Accept' }).click();
  await A.waitForFunction(() => window.__saved['note.txt']);
  assert((await A.evaluate(() => window.__saved['note.txt'].sha)) === sha(note), 'note matches');
  ok('second computer joins by typing the session code and transfers');

  // ---------- a third device is refused, gets its own session ----------
  const D = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage(); watch(D, 'third');
  await D.goto(`${SCHEME}://127.0.0.1:${port}/?s=${session}`);
  await D.locator('.toast', { hasText: 'already has two devices' }).waitFor();
  await D.waitForFunction((s) => window.ezxfer.session && window.ezxfer.session !== s, session);
  ok('third device is told the session is full and gets a new one');

  // ---------- unknown code falls back to a fresh session ----------
  const E = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage(); watch(E, 'stale');
  await E.goto(`${SCHEME}://127.0.0.1:${port}/?s=NOPE99`);
  await E.locator('.toast', { hasText: 'not found' }).waitFor();
  await E.waitForFunction(() => window.ezxfer.session && window.ezxfer.session !== 'NOPE99');
  ok('stale session link falls back to a new session');

  // ---------- server upgraded while a page stays open ----------
  // An open page reconnects to a restarted server by itself. If the server now
  // serves a different page, the old one must reload instead of speaking an
  // outdated protocol to the new one.
  const tplPath = path.join(OUT, 'index-next.html');
  fs.writeFileSync(tplPath, fs.readFileSync(path.join(here, '..', 'web', 'index.html'), 'utf8')
    .replace('</body>', '<!-- next-build-marker --></body>'));
  server.kill('SIGTERM');
  await new Promise((r) => server.once('exit', r));
  server = spawn(BIN, ['-p', String(port), '--quiet', ...certArgs, '--web', tplPath], { stdio: 'inherit' });
  await C.waitForFunction(() => document.documentElement.innerHTML.includes('next-build-marker'), null, { timeout: 20000 });
  await C.waitForFunction(() => window.ezxfer && window.ezxfer.session);
  ok('page left open across a server upgrade reloads itself');

  // ---------- server restart: clients reconnect automatically ----------
  // (the old session is gone, so the page creates a new one)
  server.kill('SIGTERM');
  await new Promise((r) => server.once('exit', r));
  await A.waitForFunction(() => document.getElementById('pillText').textContent === 'Reconnecting…');
  const server2 = spawn(BIN, ['-p', String(port), '--quiet', ...certArgs], { stdio: 'inherit' });
  try {
    await A.waitForFunction((s) => window.ezxfer.session && window.ezxfer.session !== s &&
      document.getElementById('pillText').textContent === 'Waiting for device', session, { timeout: 20000 });
    ok('page reconnects after a server restart');
  } finally { server2.kill('SIGTERM'); }

  // Errors expected from deliberately broken connections are filtered out.
  const real = errors.filter((e) => !/WebSocket|ERR_CONNECTION|Failed to load resource/.test(e));
  assert(real.length === 0, 'no page errors:\n' + real.join('\n'));
  ok('no JavaScript errors in any page');
} catch (e) {
  console.error(e);
  console.error('page errors:', errors);
  process.exitCode = 1;
} finally {
  await browser.close();
  if (server.exitCode === null) server.kill('SIGTERM');
}
console.log(`e2e tests: ${passed} passed${process.exitCode ? ', FAILED' : ''} (screenshots in ${OUT})`);
