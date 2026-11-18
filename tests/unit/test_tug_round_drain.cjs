'use strict';
// Runs the actual patched game, HTTP and WebSocket code with an injected DB port.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const project = process.env.SKY_TEST_TUG_PROJECT;
const pause = ms => new Promise(r => setTimeout(r, ms));

test('TUG drains a real round, acknowledges only committed scores, and reconnects after resume',
  { skip: !project, timeout: 12000 }, async t => {
    const { createTugServer } = require(path.join(project, 'server.js'));
    const WebSocket = require(require.resolve('ws', { paths: [project] }));
    let now = 10000, commit, saves = 0;
    const records = [];
    const scores = { async summary() { return { rounds: records.length }; }, async recentRounds() { return records; },
      async saveRound(r) { saves++; await new Promise(r => { commit = r; }); records.push(r); }, async close() {} };
    const binding = { organization_id: 'test', application_id: 'tug' };
    const app = createTugServer({ clock: () => now, room: { countdownMs: 100, roundMs: 100, resultMs: 100 },
      scores, noControlListener: true, migration: { controller_id: 'game', binding } });
    t.after(() => app.closeAll());
    await new Promise(r => app.listen(0, '127.0.0.1', r));
    let generation = null;
    const control = async action => {
      const r = await app.migration.control({ schema_version: 1, controller_id: 'game', action,
        expected_generation: generation, expected_binding: binding, target_binding: null,
        request_id: randomBytes(16).toString('hex') });
      generation = r.generation; return r;
    };
    const url = 'http://127.0.0.1:' + app.address().port;
    const closed = await fetch(url + '/health').then(r => r.json());
    assert.equal(closed.writesBlocked, true); assert.equal(closed.storage, 'postgresql');
    await control('quiesce'); await control('probe'); await control('resume');
    const players = [];
    for (let i = 0; i < 2; i++) {
      const ws = new WebSocket(url.replace('http:', 'ws:') + '/ws');
      const messages = [];
      ws.on('message', data => messages.push(JSON.parse(data)));
      await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
      ws.send(JSON.stringify({ type: 'join' })); players.push({ ws, messages });
    }
    await pause(120); now += 150; await pause(100);
    assert.equal(app.room.snapshot(now).phase, 'playing');
    players[0].ws.send(JSON.stringify({ type: 'tap', n: 2 })); await pause(30);
    let drained = false;
    const closing = control('quiesce').then(r => { drained = true; return r; });
    assert.equal(app.migration.canJoin, false);
    now += 150; await pause(120);
    assert.equal(saves, 1); assert.equal(drained, false);
    assert.equal(players.some(p => p.messages.some(m => m.type === 'result')), false);
    commit(); await closing; await pause(50);
    assert.equal(records.length, 1);
    assert.equal(players.every(p => p.messages.some(m => m.type === 'result')), true);
    assert.equal(app.migration.closed, true);
    assert.equal((await fetch(url + '/api/scoreboard').then(r => r.json())).rounds, 1);
    await control('probe'); await control('resume');
    const next = new WebSocket(url.replace('http:', 'ws:') + '/ws');
    await new Promise((resolve, reject) => { next.once('open', resolve); next.once('error', reject); });
    next.terminate();
  });
