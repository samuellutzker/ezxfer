// QR code encoder for the page, a port of src/qr.c (byte mode, versions 1-40).
// The page draws its QR code itself so that the encryption key in the join
// link never goes to the server. tests/test_qr_js.mjs checks it against the C
// encoder module for module.
'use strict';
(function (root) {
  // Error-correction codewords per block and number of blocks, indexed [ecl][version].
  const ECC_PER_BLOCK = [
    [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  ];
  const NUM_BLOCKS = [
    [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
  ];
  const FORMAT_BITS = [1, 0, 3, 2];  // L, M, Q, H

  function rawModules(ver) {
    let r = (16 * ver + 128) * ver + 64;
    if (ver >= 2) { const na = Math.floor(ver / 7) + 2; r -= (25 * na - 10) * na - 55; if (ver >= 7) r -= 36; }
    return r;
  }
  const dataCodewords = (ver, ecl) => (rawModules(ver) >> 3) - ECC_PER_BLOCK[ecl][ver] * NUM_BLOCKS[ecl][ver];

  // Reed-Solomon over GF(2^8), polynomial 0x11D
  function gfMul(x, y) {
    let z = 0;
    for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >> 7) * 0x11D); z ^= ((y >> i) & 1) * x; }
    return z;
  }
  function rsDivisor(degree) {
    const res = new Array(degree).fill(0); res[degree - 1] = 1;
    for (let i = 0, root = 1; i < degree; i++, root = gfMul(root, 2))
      for (let j = 0; j < degree; j++) { res[j] = gfMul(res[j], root); if (j + 1 < degree) res[j] ^= res[j + 1]; }
    return res;
  }
  function rsRemainder(data, div) {
    const res = new Array(div.length).fill(0);
    for (const b of data) {
      const f = b ^ res.shift(); res.push(0);
      div.forEach((d, j) => { res[j] ^= gfMul(d, f); });
    }
    return res;
  }

  const MASKS = [
    (x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => x * y % 2 + x * y % 3 === 0,
    (x, y) => (x * y % 2 + x * y % 3) % 2 === 0, (x, y) => ((x + y) % 2 + x * y % 3) % 2 === 0,
  ];

  // Encodes a string (as UTF-8) or bytes. Returns { version, ecl, mask, size, mod }
  // with mod[y][x] = 1 for dark modules. Same parameters as qr_encode() in src/qr.c.
  function encode(text, ecl = 1, boost = true, forceMask = -1) {
    const data = typeof text === 'string' ? new TextEncoder().encode(text) : text;
    let ver, need = 0;
    for (ver = 1; ver <= 40; ver++) {
      const cc = ver <= 9 ? 8 : 16;
      if (data.length >= 1 << cc) continue;
      need = 4 + cc + 8 * data.length;
      if (need <= dataCodewords(ver, ecl) * 8) break;
    }
    if (ver > 40) throw new Error('too long for a QR code');
    if (boost) for (let e = ecl + 1; e <= 3; e++) if (need <= dataCodewords(ver, e) * 8) ecl = e;

    // data codewords: mode, length, bytes, terminator, padding
    const bits = [];
    const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
    const cap = dataCodewords(ver, ecl) * 8;
    put(4, 4); put(data.length, ver <= 9 ? 8 : 16);
    data.forEach((b) => put(b, 8));
    put(0, Math.min(4, cap - bits.length));
    put(0, (8 - bits.length % 8) % 8);
    for (let pad = 0xEC; bits.length < cap; pad ^= 0xEC ^ 0x11) put(pad, 8);
    const cw = [];
    for (let i = 0; i < bits.length; i += 8) cw.push(parseInt(bits.slice(i, i + 8).join(''), 2));

    // split into blocks, add error correction, interleave
    const nb = NUM_BLOCKS[ecl][ver], eccLen = ECC_PER_BLOCK[ecl][ver], raw = rawModules(ver) >> 3;
    const nShort = nb - raw % nb, shortLen = Math.floor(raw / nb), div = rsDivisor(eccLen);
    const blocks = [];
    for (let i = 0, k = 0; i < nb; i++) {
      const len = shortLen - eccLen + (i < nShort ? 0 : 1);
      const d = cw.slice(k, k += len);
      blocks.push({ d, e: rsRemainder(d, div) });
    }
    const out = [];
    for (let i = 0; i <= shortLen - eccLen; i++) for (const b of blocks) if (i < b.d.length) out.push(b.d[i]);
    for (let i = 0; i < eccLen; i++) for (const b of blocks) out.push(b.e[i]);

    // function patterns
    const size = 17 + 4 * ver;
    const mod = Array.from({ length: size }, () => new Uint8Array(size));
    const fn = Array.from({ length: size }, () => new Uint8Array(size));
    const setFn = (x, y, dark) => { mod[y][x] = dark ? 1 : 0; fn[y][x] = 1; };
    for (let i = 0; i < size; i++) { setFn(6, i, i % 2 === 0); setFn(i, 6, i % 2 === 0); }
    for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]])
      for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && y >= 0 && x < size && y < size) setFn(x, y, d !== 2 && d !== 4);
      }
    if (ver > 1) {
      const n = Math.floor(ver / 7) + 2;
      const step = ver === 32 ? 26 : Math.floor((ver * 4 + n * 2 + 1) / (n * 2 - 2)) * 2;
      const pos = [6];
      for (let i = n - 1, p = size - 7; i >= 1; i--, p -= step) pos[i] = p;
      for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
        for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
          setFn(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
    const drawFormat = (mask) => {
      const v = FORMAT_BITS[ecl] << 3 | mask;
      let rem = v;
      for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
      const b = (v << 10 | rem) ^ 0x5412, bit = (i) => (b >> i) & 1;
      for (let i = 0; i <= 5; i++) setFn(8, i, bit(i));
      setFn(8, 7, bit(6)); setFn(8, 8, bit(7)); setFn(7, 8, bit(8));
      for (let i = 9; i < 15; i++) setFn(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) setFn(size - 1 - i, 8, bit(i));
      for (let i = 8; i < 15; i++) setFn(8, size - 15 + i, bit(i));
      setFn(8, size - 8, 1);
    };
    drawFormat(0);  // reserves the area; the real bits are drawn after masking
    if (ver >= 7) {
      let rem = ver;
      for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
      const b = ver * 4096 + rem;
      for (let i = 0; i < 18; i++) {
        const bit = Math.floor(b / 2 ** i) & 1, a = size - 11 + i % 3, c = Math.floor(i / 3);
        setFn(a, c, bit); setFn(c, a, bit);
      }
    }

    // codewords in the zigzag order
    let i = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
        const x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
        if (!fn[y][x] && i < out.length * 8) { mod[y][x] = (out[i >> 3] >> (7 - (i & 7))) & 1; i++; }
      }
    }

    const applyMask = (m) => {
      for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && MASKS[m](x, y)) mod[y][x] ^= 1;
    };
    let mask = forceMask;
    if (!(mask >= 0 && mask <= 7)) {
      let best = Infinity;
      for (let m = 0; m < 8; m++) {
        applyMask(m); drawFormat(m);
        const p = penalty(mod, size);
        if (p < best) { best = p; mask = m; }
        applyMask(m);
      }
    }
    applyMask(mask); drawFormat(mask);
    return { version: ver, ecl, mask, size, mod };
  }

  function penalty(mod, n) {
    let p = 0;
    for (let t = 0; t < 2; t++) for (let b = 0; b < n; b++) {
      const at = (a) => (a < 0 || a >= n ? 0 : t ? mod[a][b] : mod[b][a]);
      let run = 1;  // runs of five or more same-coloured modules
      for (let a = 1; a < n; a++) {
        if (at(a) === at(a - 1)) run++;
        else { if (run >= 5) p += run - 2; run = 1; }
      }
      if (run >= 5) p += run - 2;
      for (let a = 0; a + 7 <= n; a++) {  // finder-like 1:1:3:1:1 with 4 light modules on a side
        if (![1, 0, 1, 1, 1, 0, 1].every((v, k) => at(a + k) === v)) continue;
        let before = true, after = true;
        for (let d = 1; d <= 4; d++) { before = before && !at(a - d); after = after && !at(a + 6 + d); }
        if (before || after) p += 40;
      }
    }
    let dark = 0;
    for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
      dark += mod[y][x];
      if (y + 1 < n && x + 1 < n) {
        const c = mod[y][x];
        if (c === mod[y][x + 1] && c === mod[y + 1][x] && c === mod[y + 1][x + 1]) p += 3;  // 2x2 blocks
      }
    }
    const total = n * n, dev = Math.abs(dark * 20 - total * 10);  // dark/light balance
    return p + (Math.ceil(dev / total) - 1) * 10;
  }

  // An SVG document, like qr_to_svg() in src/qr.c.
  function svg(text, border = 4) {
    const q = encode(text), dim = q.size + 2 * border;
    let d = '';
    for (let y = 0; y < q.size; y++) for (let x = 0; x < q.size;) {
      if (!q.mod[y][x]) { x++; continue; }
      let run = 1;
      while (x + run < q.size && q.mod[y][x + run]) run++;
      d += `M${x + border},${y + border}h${run}v1h-${run}z`;
      x += run;
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges">` +
      `<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="${d}"/></svg>`;
  }

  root.QR = Object.freeze({ encode, svg });
})(typeof window !== 'undefined' ? window : globalThis);
