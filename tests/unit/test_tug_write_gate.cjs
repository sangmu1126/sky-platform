'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { createGate } = require('../../src/assets/runtime/tug-write-gate.cjs');
const binding = { organization_id: 'org', application_id: 'game', location: { provider: 'aws' } };
function setup(hooks = {}) {
  const gate = createGate({ controller_id: 'registered-game', binding },
    { drain: async () => {}, probe: async () => true, ...hooks });
  let generation = null;
  const command = action => ({ schema_version: 1, controller_id: 'registered-game',
    expected_binding: binding, expected_generation: generation, request_id: randomBytes(16).toString('hex'),
    action, target_binding: null });
  return { gate, command, call: async action => { const r = await gate.control(command(action)); generation = r.generation; return r; } };
}
test('restart is closed and needs a quiesce + actual read before opening', async () => {
  const { gate, call, command } = setup();
  assert.equal(gate.canJoin, false);
  await call('quiesce');
  await assert.rejects(gate.control(command('resume')));
  await call('probe');
  await call('resume');
  assert.equal(gate.canJoin, true);
  assert.equal(gate.canPlay, true);
});
test('drain stops new joins while allowing the current round to finish', async () => {
  let release;
  let wait = false;
  const { gate, call } = setup({ drain: () => wait ? new Promise(r => { release = r; }) : Promise.resolve() });
  await call('quiesce'); await call('probe'); await call('resume');
  wait = true;
  const draining = call('quiesce');
  assert.equal(gate.canJoin, false); assert.equal(gate.canPlay, true); assert.equal(gate.draining, true);
  release(); await draining;
  assert.equal(gate.canPlay, false);
});
test('unknown write/drain error stays closed and cannot be resumed', async () => {
  const { gate, call } = setup({ drain: async () => { throw new Error('private-password'); } });
  await assert.rejects(call('quiesce'), error => !error.message.includes('private-password'));
  assert.equal(gate.canJoin, false); assert.equal(gate.canPlay, false);
  await assert.rejects(call('quiesce'));
});
test('bad database probe stays closed and uncertain', async () => {
  const { gate, call } = setup({ probe: async () => false });
  await call('quiesce'); await assert.rejects(call('probe')); await assert.rejects(call('resume'));
  assert.equal(gate.closed, true);
});
test('foreign, stale, replayed and rebind requests have no effect', async () => {
  const { gate, call, command } = setup();
  const first = command('quiesce'); await gate.control(first);
  await assert.rejects(gate.control(first));
  const second = await call('quiesce');
  for (const overrides of [{ expected_generation: second.generation - 1 }, { controller_id: 'other' },
    { target_binding: binding }, { expected_binding: { ...binding, application_id: 'other' } },
    { request_id: 'z'.repeat(32) }, { action: 'activate' }, { extra: true }]) {
    await assert.rejects(gate.control({ ...command('probe'), ...overrides }));
  }
  assert.equal(gate.closed, true);
});
test('concurrent controller is rejected while drain awaits', async () => {
  let release;
  const { gate, command, call } = setup({ drain: () => new Promise(r => { release = r; }) });
  const first = call('quiesce');
  await assert.rejects(gate.control(command('quiesce')));
  release(); await first;
});
