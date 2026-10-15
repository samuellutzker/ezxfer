// Test helper: encode stdin with web/qr.js and print the matrix.
// Usage: node tests/qrgen.cjs <ecl 0-3> <mask -1..7> < data
// Output: "<version> <ecl> <mask>" then one line of 0/1 per row.
require('../web/qr.js');
const [ecl, mask] = process.argv.slice(2).map(Number);
let q;
try { q = globalThis.QR.encode(require('fs').readFileSync(0), ecl, false, mask); }
catch (_) { console.log('TOO_LONG'); process.exit(1); }
console.log(`${q.version} ${q.ecl} ${q.mask}\n` + q.mod.map((r) => r.join('')).join('\n'));
