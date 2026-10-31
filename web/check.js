// ezxfer integrity check: CRC32 checksums of each 1 MB chunk of a file.
//
// The sender checksums every chunk it reads and sends a fingerprint of all of
// them with "eof". The receiver checksums every chunk it receives, compares
// fingerprints before it reports the file as received, and where the saved
// file can be read back, checks that too. So damage anywhere on the way, in
// the network, the browser or the file it writes, shows up as an error instead
// of a silently broken file.
//
// CRC32 rather than SHA-256: it works without HTTPS (WebCrypto doesn't) and
// reliably catches accidental damage. Deliberate tampering is what end-to-end
// encryption (e2e.js) is for.
//
// Loaded by index.html as a classic script (sets window.Check) and unit-tested
// in tests/test_check.mjs.
'use strict';
(function (root) {
  const CHUNK = 1024 * 1024;  // must match the page's chunk size

  // Slicing-by-8 tables for CRC-32 (IEEE 802.3, as used by zip and PNG).
  const T = new Int32Array(8 * 256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    T[n] = c;
  }
  for (let n = 0; n < 256; n++) for (let t = 1; t < 8; t++) T[t * 256 + n] = (T[(t - 1) * 256 + n] >>> 8) ^ T[T[(t - 1) * 256 + n] & 0xFF];

  function crc32(bytes) {
    let c = -1, i = 0;
    const n8 = bytes.length & ~7;
    for (; i < n8; i += 8) {
      const a = c ^ (bytes[i] | bytes[i + 1] << 8 | bytes[i + 2] << 16 | bytes[i + 3] << 24);
      c = T[1792 + (a & 0xFF)] ^ T[1536 + (a >>> 8 & 0xFF)] ^ T[1280 + (a >>> 16 & 0xFF)] ^ T[1024 + (a >>> 24)] ^
          T[768 + bytes[i + 4]] ^ T[512 + bytes[i + 5]] ^ T[256 + bytes[i + 6]] ^ T[bytes[i + 7]];
    }
    for (; i < bytes.length; i++) c = T[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ -1) >>> 0;
  }

  // One number for the whole file: the CRC32 of its chunks' CRC32s.
  function fingerprint(crcs, size) {
    const n = Math.ceil(size / CHUNK), b = new Uint8Array(4 * n), v = new DataView(b.buffer);
    for (let i = 0; i < n; i++) v.setUint32(4 * i, crcs[i] === undefined ? 0 : crcs[i]);
    return crc32(b);
  }

  // Reads a saved file (Blob/File) back and checks it chunk by chunk.
  // Resolves true if size and every chunk match; onProgress(bytes) as it goes.
  async function verify(file, crcs, size, onProgress) {
    if (file.size !== size) return false;
    for (let off = 0, i = 0; off < size; off += CHUNK, i++) {
      const bytes = new Uint8Array(await file.slice(off, Math.min(off + CHUNK, size)).arrayBuffer());
      if (crc32(bytes) !== crcs[i]) return false;
      if (onProgress) onProgress(off + bytes.length);
    }
    return true;
  }

  root.Check = Object.freeze({ CHUNK, crc32, fingerprint, verify });
})(typeof window !== 'undefined' ? window : globalThis);
