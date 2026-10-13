// Unit tests for web/qr.js. test_qr_reference.py also compares it module for
// module with a reference encoder across all versions, levels and masks.
// Run: node --test tests/test_qr_js.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';

createRequire(import.meta.url)('../web/qr.js');  // classic script: sets globalThis.QR
const QR = globalThis.QR;
const L = 0, M = 1, Q = 2, H = 3;
const letters = (n) => new TextEncoder().encode('abcdefghijklmnopqrstuvwxyz'.repeat(120).slice(0, n));
const finderAt = (q, x0, y0) => [...Array(7)].every((_, dy) => [...Array(7)].every((_, dx) => {
  const ring = dx === 0 || dy === 0 || dx === 6 || dy === 6, core = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
  return q.mod[y0 + dy][x0 + dx] === (ring || core ? 1 : 0);
}));

test('each version holds exactly its byte capacity', () => {
  for (const [ver, ecl, cap] of [[1, L, 17], [1, M, 14], [1, Q, 11], [1, H, 7], [2, M, 26], [5, Q, 60],
    [10, M, 213], [10, L, 271], [25, H, 535], [40, L, 2953], [40, H, 1273]]) {
    assert.equal(QR.encode(letters(cap), ecl, false).version, ver, `${cap} bytes`);
    if (ver < 40) assert.equal(QR.encode(letters(cap + 1), ecl, false).version, ver + 1);
    else assert.throws(() => QR.encode(letters(cap + 1), ecl, false), /too long/);
  }
});

test('function patterns: finders, timing lines, dark module', () => {
  for (const len of [10, 200]) {  // 200 bytes: version 7+, which adds version information
    const q = QR.encode(letters(len));
    assert.equal(q.size, 17 + 4 * q.version);
    assert.ok(finderAt(q, 0, 0) && finderAt(q, q.size - 7, 0) && finderAt(q, 0, q.size - 7));
    for (let i = 8; i < q.size - 8; i++) assert.ok(q.mod[6][i] === (i + 1) % 2 && q.mod[i][6] === (i + 1) % 2, `timing ${i}`);
    assert.equal(q.mod[q.size - 8][8], 1);
  }
});

test('the page gets the highest error correction that fits, a forced mask is used', () => {
  assert.deepEqual([QR.encode('hi', L).version, QR.encode('hi', L).ecl], [1, H]);  // boosted by default
  assert.equal(QR.encode('hi', L, false).ecl, L);
  assert.equal(QR.encode('').version, 1);
  const url = 'http://192.168.1.23:8080/?s=K7PQ2M';
  const a = QR.encode(url, M, false, 2), b = QR.encode(url, M, false, 5);
  assert.deepEqual([a.mask, b.mask], [2, 5]);
  assert.notDeepEqual(a.mod, b.mod);
  assert.ok(QR.encode(url).mask >= 0 && QR.encode(url).mask <= 7);
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
