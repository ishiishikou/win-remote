import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import tls from 'node:tls';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';

// G1 laboratory proof only. Never bind this unauthenticated probe to a LAN address.
const HOST = '127.0.0.1';
const dir = mkdtempSync(path.join(os.tmpdir(), 'win-remote-g1-'));
let server;
let assertions = 0;

function openssl(...args) {
  execFileSync('openssl', args, { cwd: dir, stdio: 'pipe', timeout: 20_000 });
}

function generateCertificate() {
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-days', '1', '-subj', '/CN=win-remote-G1-test-CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-keyout', 'ca.key', '-out', 'ca.crt');
  openssl('req', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-subj', '/CN=win-remote-G1-test', '-keyout', 'server.key', '-out', 'server.csr');
  writeFileSync(path.join(dir, 'server.ext'), [
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=critical,digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth',
    'subjectAltName=IP:127.0.0.1',
    ''
  ].join('\n'));
  openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt',
    '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-sha256',
    '-extfile', 'server.ext', '-out', 'server.crt');
  return {
    key: readFileSync(path.join(dir, 'server.key')),
    cert: readFileSync(path.join(dir, 'server.crt')),
    ca: readFileSync(path.join(dir, 'ca.crt'))
  };
}

function get(port, ca, servername) {
  return new Promise(resolve => {
    const request = https.get({hostname: HOST, port, path: '/health',
      ...(ca ? {ca} : {}), ...(servername ? {servername} : {}),
      timeout: 5000}, response => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', chunk => {text += chunk;});
      response.on('end', () => resolve({status: response.statusCode, body: text}));
    });
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', error => resolve({error: error.code || error.message}));
  });
}

function upgrade(port, ca, origin, pathname = '/wss-probe') {
  return new Promise(resolve => {
    const client = tls.connect({host: HOST, port, ca,
      rejectUnauthorized: true, checkServerIdentity: (_, certificate) => tls.checkServerIdentity(HOST, certificate)});
    let complete = false;
    let response = '';
    const finish = result => {
      if (complete) return;
      complete = true;
      client.destroy();
      resolve(result);
    };
    client.on('secureConnect', () => {
      if (!client.authorized) return finish('TLS_UNAUTHORIZED');
      const key = randomBytes(16).toString('base64');
      client.write([
        `GET ${pathname} HTTP/1.1`, `Host: ${HOST}:${port}`,
        'Upgrade: websocket', 'Connection: Upgrade',
        `Sec-WebSocket-Key: ${key}`, 'Sec-WebSocket-Version: 13',
        `Origin: ${origin}`, '', ''
      ].join('\r\n'));
    });
    client.on('data', data => {
      response += data.toString('latin1');
      const end = response.indexOf('\r\n\r\n');
      if (end !== -1) finish(response.slice(0, end));
    });
    client.on('timeout', () => finish('TIMEOUT'));
    client.on('error', error => finish(error.code || error.message));
    client.on('end', () => finish(response || 'EARLY_END'));
    client.setTimeout(5000);
  });
}

try {
  const {key, cert, ca} = generateCertificate();
  server = https.createServer({key, cert, minVersion: 'TLSv1.2'}, (req, res) => {
    if (req.method !== 'GET' || req.url !== '/health') {
      res.writeHead(404); res.end(); return;
    }
    res.writeHead(200, {'Content-Type': 'text/plain', 'Cache-Control': 'no-store'});
    res.end('G1_LOOPBACK_ONLY');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, HOST, resolve);
  });
  const addr = server.address();
  assert.equal(addr.address, HOST); assertions++;
  const port = addr.port;
  const expectedOrigin = `https://${HOST}:${port}`;
  server.on('upgrade', (req, socket) => {
    if (req.url !== '/wss-probe' || req.headers.origin !== expectedOrigin ||
        req.headers.host !== `${HOST}:${port}` ||
        String(req.headers.upgrade).toLowerCase() !== 'websocket' ||
        !/^[a-zA-Z0-9+/]{22}==$/.test(req.headers['sec-websocket-key'] || '')) {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] +
      '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n' +
      'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  });

  assert.deepEqual(await get(port, ca), {status: 200, body: 'G1_LOOPBACK_ONLY'}); assertions++;
  assert.ok((await get(port)).error, 'untrusted CA must fail'); assertions++;
  assert.equal((await get(port, ca, 'wrong.example')).error, 'ERR_TLS_CERT_ALTNAME_INVALID'); assertions++;
  assert.match(await upgrade(port, ca, expectedOrigin), /^HTTP\/1\.1 101 /); assertions++;
  assert.match(await upgrade(port, ca, 'https://evil.example'), /^HTTP\/1\.1 403 /); assertions++;
  assert.match(await upgrade(port, ca, expectedOrigin, '/command'), /^HTTP\/1\.1 403 /); assertions++;
  console.log(`G1 loopback laboratory proof: ${assertions} checks passed; no LAN listener; no persistent keys.`);
} finally {
  if (server?.listening) {
    server.close();
    await once(server, 'close');
  }
  rmSync(dir, {recursive: true, force: true});
}
