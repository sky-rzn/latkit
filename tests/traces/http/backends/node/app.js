// SPDX-License-Identifier: GPL-2.0
// М0 trace-corpus backend: node + express (a third HTTP/1.1 server writer,
// distinct from Go net/http and from gunicorn/werkzeug).
//
//   node backends/node/app.js --addr 8083
//
// Same route contract as backends/go; no hijack-only routes (CONNECT and the
// raw 101 upgrade live in the Go backend).
'use strict';
const express = require('express');

const idx = process.argv.indexOf('--addr');
const PORT = idx > 0 ? Number(process.argv[idx + 1]) : 8083;
const FILLER = '0123456789abcdef';

const app = express();
app.disable('etag');
app.disable('x-powered-by');

app.all(['/hello', '/hello.txt'], (req, res) => {
    res.type('text/plain').send(`hello from node, method=${req.method}\n`);
});

app.all(/^\/json\//, (req, res) => { // regex, not a pattern: express 4 and 5 differ
    res.json({ id: req.path.slice('/json/'.length), q: req.url.split('?')[1] || '' });
});

// Known length: express sets Content-Length for a buffer/string body.
app.get('/big', (req, res) => {
    const n = intQuery(req, 'n', 1 << 20);
    res.type('application/octet-stream').send(Buffer.alloc(n, FILLER));
});

// Reconnaissance item 2: bypass express' res.send (which sets Content-Length)
// and answer through the core http response — node's own default framing.
app.get('/auto', (req, res) => {
    const n = intQuery(req, 'n', 1024);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(Buffer.alloc(n, FILLER));
});

// res.write() without Content-Length => node frames the response chunked.
app.get('/chunked', (req, res) => {
    const n = intQuery(req, 'n', 5);
    res.type('text/plain');
    let i = 0;
    const tick = () => {
        if (i >= n) return res.end();
        res.write(`chunk ${i} of ${n}\n`);
        i += 1;
        setTimeout(tick, 5);
    };
    tick();
});

// Body sink; node answers Expect: 100-continue automatically (no
// 'checkContinue' listener is installed).
app.post('/echo', (req, res) => {
    let n = 0;
    req.on('data', (b) => { n += b.length; });
    req.on('end', () => {
        res.type('text/plain').send(
            `read ${n} bytes, te=${req.headers['transfer-encoding'] || '-'}\n`);
    });
});

app.get('/redirect', (req, res) => res.redirect(302, '/hello'));
app.get('/boom', (req, res) => res.status(500).type('text/plain').send('boom\n'));

app.get('/slow', (req, res) => {
    setTimeout(() => res.type('text/plain').send('slow ok\n'), intQuery(req, 'ms', 200));
});

// Promise n bytes, deliver 1 KB, destroy the socket: "разрыв посреди тела".
app.get('/truncate', (req, res) => {
    const n = intQuery(req, 'n', 1 << 16);
    res.socket.write(
        'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n' +
        `Content-Length: ${n}\r\n\r\n` + FILLER.repeat(64));
    setTimeout(() => res.socket.destroy(), 20);
});

function intQuery(req, key, def) {
    const v = Number(req.query[key]);
    return Number.isFinite(v) && v >= 0 ? v : def;
}

const server = app.listen(PORT, () => console.log(`node backend listening on ${PORT}`));
server.headersTimeout = 30000;
server.maxHeaderSize = 1 << 20; // 16 KB header blocks are a corpus scenario
