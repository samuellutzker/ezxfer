// ezxfer end-to-end encryption. All cryptography of the app is in this file.
//
// With encryption on, the two browsers share a key the server never sees. It
// travels in the QR code / link after "#" (browsers never send that part to a
// server) or is typed in by the user. Every message to the other device is
// sealed here with AES-256-GCM before it reaches the network: the server only
// relays boxes it cannot open, and any change to a box makes opening it fail.
//
// Loaded by index.html as a classic script (sets window.E2E) and unit-tested in
// tests/test_crypto.mjs.
//
// To check that the server can't read anything:
// - The key is made in the browser, by newKey() below (crypto.getRandomValues).
//   The server never sends one. index.html shows it on screen, puts it in the
//   link after "#", and keeps it in sessionStorage; it never sends it.
// - index.html writes to the network in exactly two places: toServer() (only
//   "ping" and the handshake, whose key check is a sealed box) and wire(). In
//   an encrypted session wire() throws on anything that isn't a Sealed box, and
//   only seal() below can create one.
// - The AES keys are derived inside channel() and never leave it.
'use strict';
(function (root) {
  const crypto = root.crypto;
  const subtle = crypto && crypto.subtle;             // browsers only offer it on HTTPS / localhost
  const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 unambiguous symbols, 5 bits each
  const KEY_CHARS = 20;                                // 100 bits of randomness
  const IV_BYTES = 12, TAG_BYTES = 16;
  const enc = new TextEncoder(), dec = new TextDecoder();

  // Additional authenticated data separates the kinds of boxes, so one can't be
  // passed off as another. File chunks use their 12-byte header (transfer id,
  // byte offset) instead, which also ties each chunk to its place in the file.
  const AAD_MESSAGE = enc.encode('msg');
  const AAD_CHECK = enc.encode('check');
  const CHECK_TEXT = 'ezxfer key check';

  // The only type the page sends to the other device while encryption is on.
  // Only seal() below can make one: it alone holds SEAL.
  const SEAL = Symbol('seal');
  class Sealed {
    constructor(token, bytes) {
      if (token !== SEAL) throw new TypeError('only E2E can seal');
      this.bytes = bytes;
      Object.freeze(this);
    }
  }

  // ---- keys ----

  // A fresh random key, e.g. "K7PQ2-M9XAB-3HJWE-RT5VC".
  function newKey() {
    const r = crypto.getRandomValues(new Uint8Array(KEY_CHARS));
    return formatKey(Array.from(r, (b) => ALPHABET[b % 32]).join(''));  // 256 % 32 == 0: unbiased
  }

  // Accepts what a user types (any case, with or without dashes or spaces).
  // Returns the 20 key characters, or null if it can't be a key.
  function normalizeKey(text) {
    const s = String(text || '').toUpperCase().replace(/[\s-]/g, '');
    return s.length === KEY_CHARS && [...s].every((c) => ALPHABET.includes(c)) ? s : null;
  }

  function formatKey(text) {
    const k = normalizeKey(text);
    return k && k.match(/.{5}/g).join('-');
  }

  // ---- boxes: iv (12 bytes) | ciphertext | tag (16 bytes) ----

  async function seal(key, plain, aad) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));  // a fresh random nonce for every box
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plain));
    const box = new Uint8Array(IV_BYTES + ct.length);
    box.set(iv);
    box.set(ct, IV_BYTES);
    return new Sealed(SEAL, box);
  }

  // Throws if the box was altered, belongs to another kind (aad) or another key.
  async function open(key, box, aad) {
    if (box.length < IV_BYTES + TAG_BYTES) throw new Error('box too short');
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: box.subarray(0, IV_BYTES), additionalData: aad }, key, box.subarray(IV_BYTES));
    return new Uint8Array(plain);
  }

  // ---- what the page uses ----

  // The encrypted channel between this device (`me`) and the other one (`peer`),
  // both named by their client ids. Each direction gets its own AES-256 key,
  // derived with HKDF-SHA256 from the key text, salted with the session code and
  // labelled "from>to". So a box opens only on the device it was sealed for, and
  // a relay can't bounce a device's own boxes back to it. The AES keys are
  // non-extractable and stay inside this closure.
  async function channel(keyText, sessionCode, me, peer) {
    const k = normalizeKey(keyText);
    if (!k) throw new Error('invalid key');
    if (!me || !peer || me === peer) throw new Error('invalid device ids');
    const ikm = await subtle.importKey('raw', enc.encode(k), 'HKDF', false, ['deriveKey']);
    const derive = (from, to) => subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('ezxfer e2e v1|' + sessionCode), info: enc.encode(from + '>' + to) },
      ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const [tx, rx] = await Promise.all([derive(me, peer), derive(peer, me)]);
    return Object.freeze({
      // JSON messages
      sealMessage: (obj) => seal(tx, enc.encode(JSON.stringify(obj)), AAD_MESSAGE),
      openMessage: async (box) => JSON.parse(dec.decode(await open(rx, box, AAD_MESSAGE))),
      // File chunks: the header stays readable (the receiver needs it to find the
      // transfer) but is authenticated, so it can't be changed without detection.
      sealChunk: (header, data) => seal(tx, data, header),
      openChunk: (header, box) => open(rx, box, header),
      // Handshake proof: a box only a device with the same key can open. Shows
      // that both devices have the same key without revealing anything about it.
      makeCheck: async () => toB64((await seal(tx, enc.encode(CHECK_TEXT), AAD_CHECK)).bytes),
      async verifyCheck(b64) {
        try { return dec.decode(await open(rx, fromB64(b64), AAD_CHECK)) === CHECK_TEXT; } catch (_) { return false; }
      },
    });
  }

  function toB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function fromB64(b64) { return Uint8Array.from(atob(String(b64)), (c) => c.charCodeAt(0)); }

  root.E2E = Object.freeze({
    available: !!subtle, Sealed, OVERHEAD: IV_BYTES + TAG_BYTES,
    newKey, normalizeKey, formatKey, channel, toB64, fromB64,
  });
})(typeof window !== 'undefined' ? window : globalThis);
