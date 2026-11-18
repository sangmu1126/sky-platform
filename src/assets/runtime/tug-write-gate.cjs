'use strict';
// Explicit single-process TUG adaptation. No generic session migration claim.
const { randomInt, timingSafeEqual } = require('node:crypto');
const https = require('node:https');
const fs = require('node:fs');

function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}

function createGate(config, hooks) {
  if (!config || typeof config.controller_id !== 'string' || !config.controller_id || !config.binding ||
      typeof hooks.drain !== 'function' || typeof hooks.probe !== 'function') throw new Error('Registered game controller required');
  const binding = JSON.parse(JSON.stringify(config.binding));
  let closed = true, draining = false, verified = false, controlling = false, uncertain = false;
  let generation = randomInt(1, 2 ** 47);
  const nonces = new Set();
  function fail() { closed = true; verified = false; uncertain = true; }
  return {
    get canJoin() { return !closed && !draining && !uncertain; },
    get canPlay() { return !closed && !uncertain; },
    get draining() { return draining; },
    get closed() { return closed; },
    fail,
    async control(c) {
      const keys = ['schema_version', 'controller_id', 'request_id', 'action', 'expected_binding', 'expected_generation', 'target_binding'].sort();
      if (!c || canonical(Object.keys(c).sort()) !== canonical(keys) || c.schema_version !== 1 ||
          c.controller_id !== config.controller_id || canonical(c.expected_binding) !== canonical(binding) ||
          c.target_binding !== null || !['quiesce', 'probe', 'resume'].includes(c.action) ||
          typeof c.request_id !== 'string' || !/^[a-f0-9]{32}$/.test(c.request_id) ||
          nonces.has(c.request_id) || nonces.size >= 4096 || controlling || uncertain ||
          !(c.action === 'quiesce' && c.expected_generation === null ||
            Number.isSafeInteger(c.expected_generation) && c.expected_generation === generation) ||
          c.action !== 'quiesce' && !closed || c.action === 'resume' && !verified) {
        throw new Error('Controller scope or generation mismatch');
      }
      controlling = true; nonces.add(c.request_id);
      try {
        if (c.action === 'quiesce') {
          // Stop new joins immediately; let an existing round finish and commit.
          draining = true; verified = false;
          await hooks.drain();
          closed = true; draining = false;
        } else if (c.action === 'probe') {
          verified = false;
          if (await hooks.probe() !== true) throw new Error('Actual database read required');
          verified = true;
        } else {
          closed = false; verified = false; draining = false;
        }
        generation += 1;
        return { schema_version: 1, controller_id: config.controller_id, request_id: c.request_id,
          action: c.action, binding: JSON.parse(JSON.stringify(binding)), generation,
          writes_blocked: closed, active_writes: 0, database_read_verified: c.action === 'probe' && verified };
      } catch {
        fail(); throw new Error('Game controller requires reconciliation');
      } finally { controlling = false; }
    },
  };
}

function controlServer(gate, config) {
  if (typeof config.control_token !== 'string' || config.control_token.length < 32 ||
      !Number.isInteger(config.control_port) || config.control_port < 1024 || config.control_port > 65535) {
    throw new Error('Private game control configuration required');
  }
  const credential = Buffer.from('Bearer ' + config.control_token);
  const server = https.createServer({ key: fs.readFileSync(config.tls_key), cert: fs.readFileSync(config.tls_cert),
    minVersion: 'TLSv1.2' }, (req, res) => {
    const reply = (status, body) => {
      if (res.destroyed) return;
      const data = JSON.stringify(body);
      res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data),
        'Cache-Control': 'no-store', 'Connection': 'close' });
      res.end(data);
    };
    const auth = Buffer.from(req.headers.authorization || '');
    const count = name => req.rawHeaders.filter((v, i) => i % 2 === 0 && v.toLowerCase() === name).length;
    if (count('authorization') !== 1 || auth.length !== credential.length || !timingSafeEqual(auth, credential)) return reply(401, { code: 'authentication_required' });
    if (req.method !== 'POST' || req.url !== '/control') return reply(404, { code: 'unknown_control' });
    const size = Number(req.headers['content-length']);
    if (count('content-length') !== 1 || req.headers['transfer-encoding'] ||
        req.headers['content-type'] !== 'application/json' || !Number.isInteger(size) || size < 2 || size > 16384) return reply(400, { code: 'invalid_framing' });
    let parts = [], received = 0;
    req.on('data', chunk => { received += chunk.length; if (received > size) req.destroy(); else parts.push(chunk); });
    req.on('error', () => {});
    req.on('end', async () => {
      if (received !== size) return reply(400, { code: 'incomplete_request' });
      let command;
      try { command = JSON.parse(Buffer.concat(parts).toString('utf8')); }
      catch { return reply(400, { code: 'invalid_document' }); }
      try { reply(200, await gate.control(command)); }
      catch { reply(503, { code: 'control_requires_reconciliation' }); }
    });
  });
  server.headersTimeout = 5000; server.requestTimeout = 10000;
  server.on('clientError', (_err, socket) => socket.destroy());
  return server;
}

module.exports = { createGate, controlServer };
