// web/qr.js must produce exactly the symbols of the C encoder (src/qr.c), which
// test_qr_reference.py checks against a reference implementation.
// Run: node --test tests/test_qr_js.mjs   (needs build/qrgen: make build/qrgen)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';

const require = createRequire(import.meta.url);
require('../web/qr.js');  // classic script: sets globalThis.QR
const QR = globalThis.QR;
const QRGEN = new URL('../build/qrgen', import.meta.url).pathname;

function c(data, ecl, mask) {  // the C encoder's version, ecl, mask and matrix
  const [head, ...rows] = execFileSync(QRGEN, [String(ecl), String(mask)], { input: data }).toString().trim().split('\n');
  return { head, rows };
}
const js = (data, ecl, mask) => {
  const q = QR.encode(data, ecl, false, mask);
  return { head: `${q.version} ${q.ecl} ${q.mask}`, rows: q.mod.map((r) => r.join('')) };
};

test('same symbols as the C encoder for all levels, masks and many versions', () => {
  for (const len of [0, 1, 17, 30, 77, 150, 300, 600, 1200, 2300]) {
    for (let ecl = 0; ecl < 4; ecl++) {
      const data = randomBytes(len);
      if (len > 1200 && ecl > 1) continue;  // more than version 40 holds
      for (const mask of [-1, len % 8]) assert.deepEqual(js(data, ecl, mask), c(data, ecl, mask), `len ${len} ecl ${ecl} mask ${mask}`);
    }
  }
});

test('join links with a key, as the page encodes them', () => {
  for (let i = 0; i < 20; i++) {
    const url = `https://192.168.1.${i}:8443/?s=ABC${100 + i}#k=K7PQ2M9XAB3HJWERT5V${'C2345'[i % 5]}`;
    const q = QR.encode(url);  // the page's defaults: level M, boosted, automatic mask
    assert.ok(q.ecl >= 1);
    assert.deepEqual(js(new TextEncoder().encode(url), q.ecl, -1), c(url, q.ecl, -1));
  }
});

test('the SVG draws exactly the dark modules, inside a 4-module quiet zone', () => {
  const text = 'https://192.168.1.20:8443/?s=ABC123#k=K7PQ2M9XAB3HJWERT5VC';
  const q = QR.encode(text), svg = QR.svg(text), dim = q.size + 8;
  assert.ok(svg.includes(`viewBox="0 0 ${dim} ${dim}"`));
  const drawn = Array.from({ length: q.size }, () => new Uint8Array(q.size));
  for (const [, x, y, run] of svg.matchAll(/M(\d+),(\d+)h(\d+)v1h-\3z/g))
    for (let i = 0; i < +run; i++) drawn[y - 4][x - 4 + i] = 1;
  assert.deepEqual(drawn, q.mod);
  assert.throws(() => QR.encode(randomBytes(3000)), /too long/);
});
