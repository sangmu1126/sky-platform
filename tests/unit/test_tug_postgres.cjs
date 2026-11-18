'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

test('PostgreSQL bigint strings preserve the original numeric game HTTP contract', async () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'sky-tug-pg-contract-'));
  const ca = path.join(folder, 'ca.pem');fs.writeFileSync(ca, 'test trust material');
  const names = ['PGHOST','PGPORT','PGUSER','PGPASSWORD','PGDATABASE','PGSSLROOTCERT','PGSSLMODE'];
  const before = Object.fromEntries(names.map(k => [k, process.env[k]]));
  Object.assign(process.env, { PGHOST:'owned.test', PGPORT:'5432', PGUSER:'app', PGPASSWORD:'not-real',
    PGDATABASE:'game', PGSSLROOTCERT:ca, PGSSLMODE:'verify-full' });
  const queries=[];let settings;
  class Pool {
    constructor(config){settings=config;}
    on(){}
    async query(sql, params){
      queries.push({sql, params});
      if(sql.startsWith('SELECT id,'))return {rows:[{id:'14',started_at:'1793389463424',ended_at:'1793389493445',winner:'DRAW',taps_a:'119',taps_b:'119',players_a:'1',players_b:'1'}]};
      if(sql.startsWith('SELECT COUNT'))return {rows:[{rounds:14,wins_a:5,wins_b:7,draws:2,taps:'2165',best:'624'}]};
      return {rows:[]};
    }
    async end(){}
  }
  const original = Module._load;
  try {
    Module._load = function(name, ...args){return name === 'pg' ? {Pool} : original.call(this, name, ...args);};
    const {openScores}=require('../../src/assets/runtime/tug-postgres.cjs');
    Module._load=original;
    const scores=await openScores();
    assert.equal(settings.ssl.rejectUnauthorized,true);assert.equal(settings.ssl.servername,'owned.test');
    const [r]=await scores.recentRounds(5);
    assert.deepEqual(r,{id:14,startedAt:1793389463424,endedAt:1793389493445,winner:'DRAW',taps:{A:119,B:119},players:{A:1,B:1}});
    assert.equal((await scores.summary()).totalTaps,2165);
    await scores.saveRound(r);assert.equal(queries.at(-1).params[2],'DRAW');
    assert.equal(queries.some(q=>/CREATE|ALTER|DROP/.test(q.sql)),false);
    await scores.close();
  } finally {
    Module._load=original;
    for(const key of names){if(before[key]===undefined)delete process.env[key];else process.env[key]=before[key];}
    fs.rmSync(folder,{recursive:true});
  }
});
