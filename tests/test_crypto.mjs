// Unit tests for web/e2e.js (Node's built-in test runner and WebCrypto).
// Run: node --test tests/test_crypto.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';

const SOURCE = new URL('../web/e2e.js', import.meta.url);
createRequire(import.meta.url)(SOURCE.pathname);  // classic script: sets globalThis.E2E
const E2E = globalThis.E2E;
const enc = new TextEncoder();
const header = (id, offset) => {  // the 12-byte chunk header used by the page
  const h = new Uint8Array(12), dv = new DataView(h.buffer);
  dv.setUint32(0, id); dv.setUint32(4, Math.floor(offset / 2 ** 32)); dv.setUint32(8, offset >>> 0);
  return h;
};
const contains = (hay, needle) => Buffer.from(hay).includes(Buffer.from(needle));
const A = 'aaaaaaaaaaaaaaaaaaaaaaaa', B = 'bbbbbbbbbbbbbbbbbbbbbbbb';  // client ids
// Both ends of one connection: what A seals, B opens, and the other way round.
async function pair(key = E2E.newKey(), session = 'ABC123') {
  return [await E2E.channel(key, session, A, B), await E2E.channel(key, session, B, A)];
}

test('keys look like XXXXX-XXXXX-XXXXX-XXXXX, are random, and normalize', () => {
  const keys = new Set(Array.from({ length: 200 }, () => E2E.newKey()));
  assert.equal(keys.size, 200);
  // all 32 symbols are used (5 bits per character, 100 bits per key); 4000 characters miss one with p < 1e-50
  assert.equal(new Set([...keys].join('').replace(/-/g, '')).size, 32);
  for (const k of keys) {
    assert.match(k, /^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}$/);
    assert.equal(E2E.formatKey(k.toLowerCase().replace(/-/g, ' ')), k);
  }
  assert.equal(E2E.normalizeKey('k7pq2 m9xab-3hjwe RT5VC'), 'K7PQ2M9XAB3HJWERT5VC');
  for (const bad of ['', 'K7PQ2', 'K7PQ2-M9XAB-3HJWE-RT5V', 'K7PQ2-M9XAB-3HJWE-RT5VCX',
    'O7PQ2-M9XAB-3HJWE-RT5VC', '07PQ2-M9XAB-3HJWE-RT5VC', 'I7PQ2-M9XAB-3HJWE-RT5VC', null])
    assert.equal(E2E.normalizeKey(bad), null, String(bad));
});

test('only the other end of the same key and session can open a box', async () => {
  const key = E2E.newKey();
  const [a, b] = await pair(key);
  const box = (await a.sealMessage({ type: 'offer', name: 'x' })).bytes;
  assert.deepEqual(await b.openMessage(box), { type: 'offer', name: 'x' });
  const [, typedLowercase] = await pair(key.toLowerCase());
  assert.deepEqual(await typedLowercase.openMessage(box), { type: 'offer', name: 'x' });
  const [, otherSession] = await pair(key, 'ABC124');
  const [, otherKey] = await pair(E2E.newKey());
  await assert.rejects(otherSession.openMessage(box));
  await assert.rejects(otherKey.openMessage(box));
  await assert.rejects(a.openMessage(box));  // the sender can't open (or be fed) its own boxes
  await assert.rejects(E2E.channel('not a key', 'S', A, B), /invalid key/);
  await assert.rejects(E2E.channel(key, 'S', A, A), /invalid device ids/);
});

test('a channel holds no readable key material', async () => {
  const [a] = await pair();
  assert.ok(Object.isFrozen(a));
  for (const v of Object.values(a)) assert.equal(typeof v, 'function');
});

test('a sealed chunk reveals nothing of its content and opens to the original', async () => {
  const [a, b] = await pair();
  for (const size of [0, 1, 1000, 1 << 20]) {
    const data = new Uint8Array(size).fill(0x41);  // "AAAA…": easy to spot if it leaked
    const box = await a.sealChunk(header(7, 3 << 20), data);
    assert.ok(box instanceof E2E.Sealed);
    assert.equal(box.bytes.length, size + E2E.OVERHEAD);
    if (size >= 16) assert.ok(!contains(box.bytes, data.subarray(0, 16)), 'plaintext visible in box');
    assert.deepEqual(await b.openChunk(header(7, 3 << 20), box.bytes), data);
  }
});

test('every box uses a fresh nonce: the same plaintext never seals the same way', async () => {
  const [a] = await pair();
  const boxes = await Promise.all(Array.from({ length: 50 }, () => a.sealMessage({ type: 'same' })));
  const ivs = new Set(boxes.map((b) => Buffer.from(b.bytes.subarray(0, 12)).toString('hex')));
  const all = new Set(boxes.map((b) => Buffer.from(b.bytes).toString('hex')));
  assert.equal(ivs.size, 50);
  assert.equal(all.size, 50);
});

test('any change to a box, or to the chunk header it belongs to, is detected', async () => {
  const [a, b] = await pair();
  const box = (await a.sealChunk(header(1, 0), enc.encode('secret file content'))).bytes;
  for (const pos of [0, 11, 12, box.length - 17, box.length - 1]) {  // nonce, ciphertext, tag
    const t = box.slice(); t[pos] ^= 1;
    await assert.rejects(b.openChunk(header(1, 0), t), undefined, `byte ${pos}`);
  }
  await assert.rejects(b.openChunk(header(2, 0), box));        // other transfer
  await assert.rejects(b.openChunk(header(1, 1 << 20), box));  // other position in the file
  await assert.rejects(b.openChunk(header(1, 0), box.subarray(0, 20)));  // truncated
});

test('a message cannot be passed off as a file chunk, or the other way round', async () => {
  const [a, b] = await pair();
  const msg = (await a.sealMessage({ type: 'cancel', id: 1 })).bytes;
  await assert.rejects(b.openChunk(header(0, 0), msg));
  await assert.rejects(b.openChunk(enc.encode('msg'), msg), /bad chunk header/);  // not even with the message label as header
  const chunk = (await a.sealChunk(header(0, 0), enc.encode('{"type":"cancel","id":1}'))).bytes;
  await assert.rejects(b.openMessage(chunk));
  assert.equal(await b.verifyCheck(E2E.toB64(msg)), false);  // and an ordinary message is no key check
});

test('messages round-trip, including non-ASCII file names', async () => {
  const [a, b] = await pair();
  const m = { type: 'offer', id: 42, name: 'Grüße – 写真.jpg', size: 123, mime: 'image/jpeg' };
  const box = await a.sealMessage(m);
  assert.ok(!contains(box.bytes, enc.encode('jpg')));
  assert.deepEqual(await b.openMessage(box.bytes), m);
});

test('the key check tells whether both devices hold the same key', async () => {
  const key = E2E.newKey();
  const [host, joiner] = await pair(key, 'SESS01');
  const check = await host.makeCheck();
  assert.equal(await joiner.verifyCheck(check), true);
  assert.equal(await host.verifyCheck(check), false);  // a check bounced back to its sender
  const [, wrong] = await pair(E2E.newKey(), 'SESS01');
  assert.equal(await wrong.verifyCheck(check), false);
  assert.equal(await joiner.verifyCheck('garbage!'), false);
  assert.equal(await joiner.verifyCheck(''), false);
  assert.notEqual(await host.makeCheck(), check);  // fresh each time
});

test('base64 round-trips binary data of any length', () => {
  for (const n of [0, 1, 2, 3, 0x8000, 0x8001, 200000]) {  // the encoder works in 32 KB pieces
    const b = new Uint8Array(randomBytes(n));
    assert.equal(E2E.toB64(b), Buffer.from(b).toString('base64'), `length ${n}`);
    assert.deepEqual(E2E.fromB64(E2E.toB64(b)), b);
  }
});

test('without WebCrypto (browsers withhold it on plain HTTP) encryption is unavailable', () => {
  const page = vm.createContext({ crypto: { getRandomValues: (a) => crypto.getRandomValues(a) }, TextEncoder, TextDecoder, btoa, atob });
  vm.runInContext(fs.readFileSync(SOURCE, 'utf8'), page);
  assert.equal(page.E2E.available, false);  // the page then doesn't offer encryption
  assert.ok(page.E2E.normalizeKey(page.E2E.newKey()));
});

test('only E2E makes Sealed boxes, and they are immutable', async () => {
  const [a] = await pair();
  const box = await a.sealMessage({});
  assert.ok(Object.isFrozen(box));
  assert.throws(() => { box.bytes = new Uint8Array(1); });
  assert.throws(() => new E2E.Sealed(undefined, enc.encode('plaintext')), /only E2E can seal/);
  assert.ok(Object.isFrozen(E2E));
});
