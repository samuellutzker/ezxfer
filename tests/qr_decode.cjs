// decode a 0/1 matrix from stdin with jsQR
const jsQR = require('jsqr');
const lines = require('fs').readFileSync(0, 'utf8').split('\n').filter(l => /^[01]+$/.test(l));
const n = lines.length, s = 6, b = 4, dim = (n + 2 * b) * s;
const px = new Uint8ClampedArray(dim * dim * 4).fill(255);
for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (lines[y][x] === '1')
  for (let dy = 0; dy < s; dy++) for (let dx = 0; dx < s; dx++) {
    const i = (((y + b) * s + dy) * dim + (x + b) * s + dx) * 4; px[i] = px[i + 1] = px[i + 2] = 0; }
const r = jsQR(px, dim, dim);
process.stdout.write(r ? Buffer.from(r.binaryData).toString('hex') : 'FAIL');
