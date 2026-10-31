// ezxfer service worker: streams received files straight into the browser's
// download manager so phones don't have to hold whole files in memory.
//
// The page registers a download (name, size, type) together with a
// MessagePort, then opens /dl/<random> in a hidden iframe. That request
// is answered here with a streaming Response whose body is fed, chunk by
// chunk, with the data the page pushes through the port. Each chunk is
// acknowledged once the download has room for more, which gives end-to-end
// back-pressure all the way to the sending device.
'use strict';

const pending = new Map(); // path -> registered download waiting for its request

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (e) => {
  const m = e.data;
  if (!m || m.type !== 'register' || !e.ports[0]) return; // e.g. keep-alive pings
  const port = e.ports[0];
  let ctrl = null, onRoom = null;

  const stream = new ReadableStream({
    start(c) { ctrl = c; },
    // called whenever the download has consumed data and wants more
    pull() { if (onRoom) { const f = onRoom; onRoom = null; f(); } },
    // the user cancelled the download in the browser
    cancel() { port.postMessage({ type: 'cancelled' }); },
  }, { highWaterMark: 4 }); // buffer up to 4 chunks (~1 MB)

  port.onmessage = ({ data }) => {
    try {
      if (data.type === 'chunk') {
        ctrl.enqueue(new Uint8Array(data.buf));
        const ack = () => port.postMessage({ type: 'ack', seq: data.seq });
        if (ctrl.desiredSize > 0) ack(); else onRoom = ack;
      } else if (data.type === 'close') {
        ctrl.close();
        port.postMessage({ type: 'closed' });
      } else if (data.type === 'abort') {
        ctrl.error(new Error('transfer aborted'));
      }
    } catch (_) {
      port.postMessage({ type: 'cancelled' }); // stream already gone
    }
  };

  pending.set(m.path, { port, stream, name: String(m.name || 'download'), size: m.size, mime: m.mime });
  setTimeout(() => pending.delete(m.path), 30000); // never requested: forget it
  port.postMessage({ type: 'registered' });
});

self.addEventListener('fetch', (e) => {
  const path = new URL(e.request.url).pathname;
  const d = pending.get(path);
  if (!d) return; // not a download of ours: normal network request
  pending.delete(path);
  d.port.postMessage({ type: 'started' });
  const name = d.name.replace(/[\u0000-\u001f"\\/]/g, '_');
  const ascii = name.replace(/[^\x20-\x7e]/g, '_');
  const headers = {
    'Content-Type': d.mime || 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`,
    'X-Content-Type-Options': 'nosniff',
  };
  if (Number.isFinite(d.size)) headers['Content-Length'] = String(d.size); // lets the browser show progress
  e.respondWith(new Response(d.stream, { headers }));
});
