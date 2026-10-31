// Unit tests for web/check.js (the per-chunk CRC32 integrity check).
// Run: node --test tests/test_check.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import zlib from 'node:zlib';

createRequire(import.meta.url)('../web/check.js');  // classic script: sets globalThis.Check
const { CHUNK, crc32, fingerprint, verify } = globalThis.Check;
const chunkCrcs = (buf) => Array.from({ length: Math.ceil(buf.length / CHUNK) }, (_, i) => crc32(buf.subarray(i * CHUNK, (i + 1) * CHUNK)));

test('CRC-32 matches the standard (zlib) for any length and any view', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xCBF43926);  // the standard check value
  assert.equal(crc32(new Uint8Array(0)), 0);
  const data = randomBytes(70000);
  for (const [from, to] of [[0, 70000], [1, 70000], [3, 11], [7, 8], [5, 69999], [12, 12 + 65536]])
    assert.equal(crc32(data.subarray(from, to)), zlib.crc32(data.subarray(from, to)), `${from}..${to}`);
});

test('a single flipped bit anywhere changes the checksum', () => {
  const data = randomBytes(4096), c = crc32(data);
  for (const pos of [0, 1, 7, 8, 1000, 4095]) for (const bit of [0, 3, 7]) {
    const d = Buffer.from(data); d[pos] ^= 1 << bit;
    assert.notEqual(crc32(d), c, `byte ${pos} bit ${bit}`);
  }
});

test('the fingerprint covers every chunk, its order and the file size', () => {
  const crcs = [0x11111111, 0x22222222, 0x33333333], size = 2 * CHUNK + 5;
  const fp = fingerprint(crcs, size);
  assert.equal(fingerprint([...crcs], size), fp);
  assert.notEqual(fingerprint([0x11111111, 0x33333333, 0x22222222], size), fp);  // reordered
  assert.notEqual(fingerprint([0x11111111, 0x22222222, 0x33333334], size), fp);  // one chunk differs
  assert.notEqual(fingerprint(crcs.slice(0, 2), size), fp);                       // a chunk missing
  assert.notEqual(fingerprint([...crcs, 0], 3 * CHUNK + 1), fp);                  // an extra chunk
  assert.equal(fingerprint([], 0), crc32(new Uint8Array(0)));                     // empty file
});

test('verify() accepts the file as checksummed and finds any damage', async () => {
  const buf = randomBytes(3 * CHUNK + 777), crcs = chunkCrcs(buf);
  const seen = [];
  assert.equal(await verify(new Blob([buf]), crcs, buf.length, (n) => seen.push(n)), true);
  assert.deepEqual(seen, [CHUNK, 2 * CHUNK, 3 * CHUNK, buf.length]);
  for (const pos of [0, CHUNK - 1, CHUNK, 2 * CHUNK + 5, buf.length - 1]) {
    const d = Buffer.from(buf); d[pos] ^= 0x40;
    assert.equal(await verify(new Blob([d]), crcs, buf.length), false, `byte ${pos}`);
  }
  assert.equal(await verify(new Blob([buf.subarray(1)]), crcs, buf.length), false);           // truncated
  assert.equal(await verify(new Blob([buf, Buffer.from('x')]), crcs, buf.length), false);    // extra byte
  assert.equal(await verify(new Blob([]), [], 0), true);                                      // empty file
});
