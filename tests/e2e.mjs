// End-to-end browser tests (Playwright + Chromium).
// Usage: node tests/e2e.mjs ./ezxfer
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
const OUT = process.env.E2E_OUT || fs.mkdtempSync(path.join(os.tmpdir(), 'ezxfer-e2e-'));
const sha = (b) => createHash('sha256').update(b).digest('hex');
let passed = 0;
function ok(name, extra = '') { passed++; console.log(`  ok  ${name}${extra ? '  ' + extra : ''}`); }
function assert(c, msg) { if (!c) throw new Error('assertion failed: ' + msg); }

const port = await new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
const server = spawn(BIN, ['-p', String(port), '--quiet'], { stdio: 'inherit' });
await new Promise((r) => setTimeout(r, 300));

// Talk to the server directly even if an HTTP(S)_PROXY is configured.
const browserEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/_proxy$/i.test(k)));
const browser = await chromium.launch({ args: ['--no-proxy-server'], env: browserEnv });
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

const row = (page, list, name) => page.locator(`#${list} .item`, { has: page.locator('.name', { hasText: name }) });

try {
  // ---------- desktop page creates a session and shows a QR code ----------
  const desk = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  await desk.addInitScript(mockSavePicker);
  const A = await desk.newPage(); watch(A, 'desktop');
  await A.goto(`http://127.0.0.1:${port}/`);
  await A.waitForFunction(() => window.ezxfer && window.ezxfer.session);
  const session = await A.evaluate(() => window.ezxfer.session);
  const joinUrl = await A.evaluate(() => window.ezxfer.url);
  await A.waitForFunction(() => { const i = document.getElementById('qr'); return i.complete && i.naturalWidth > 0; });
  assert((await A.textContent('#code')) === session, 'session code displayed');
  assert((await A.textContent('#pillText')) === 'Waiting for device', 'waiting pill');
  assert(new URL(A.url()).searchParams.get('s') === session, 'URL carries session for reloads');
  ok('desktop shows session + QR', `session=${session}`);

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
  const phoneCtx = await browser.newContext({ ...devices['iPhone 13'], acceptDownloads: true });
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

  // ---------- another computer joins by typing the code ----------
  const other = await browser.newContext({ viewport: { width: 1000, height: 800 } });
  const C = await other.newPage(); watch(C, 'computer2');
  await C.goto(`http://127.0.0.1:${port}/`);
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
  const D = await (await browser.newContext()).newPage(); watch(D, 'third');
  await D.goto(`http://127.0.0.1:${port}/?s=${session}`);
  await D.locator('.toast', { hasText: 'already has two devices' }).waitFor();
  await D.waitForFunction((s) => window.ezxfer.session && window.ezxfer.session !== s, session);
  ok('third device is told the session is full and gets a new one');

  // ---------- unknown code falls back to a fresh session ----------
  const E = await (await browser.newContext()).newPage(); watch(E, 'stale');
  await E.goto(`http://127.0.0.1:${port}/?s=NOPE99`);
  await E.locator('.toast', { hasText: 'not found' }).waitFor();
  await E.waitForFunction(() => window.ezxfer.session && window.ezxfer.session !== 'NOPE99');
  ok('stale session link falls back to a new session');

  // ---------- server restart: clients reconnect automatically ----------
  // (the old session is gone, so the page creates a new one)
  server.kill('SIGTERM');
  await new Promise((r) => server.once('exit', r));
  await A.waitForFunction(() => document.getElementById('pillText').textContent === 'Reconnecting…');
  const server2 = spawn(BIN, ['-p', String(port), '--quiet'], { stdio: 'inherit' });
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
