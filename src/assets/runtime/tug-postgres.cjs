'use strict';
// The deployment executor creates/migrates schema; app credentials never run DDL.
const fs = require('node:fs');
const { Pool } = require('pg');

async function openScores() {
  for (const name of ['PGHOST', 'PGUSER', 'PGPASSWORD', 'PGDATABASE', 'PGSSLROOTCERT']) {
    if (!process.env[name]) throw new Error('PostgreSQL configuration incomplete');
  }
  if (process.env.PGSSLMODE && process.env.PGSSLMODE !== 'verify-full') throw new Error('Verified PostgreSQL TLS required');
  const port = Number(process.env.PGPORT || 5432);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PostgreSQL port');
  const pool = new Pool({ host: process.env.PGHOST, port, user: process.env.PGUSER,
    password: process.env.PGPASSWORD, database: process.env.PGDATABASE,
    ssl: { rejectUnauthorized: true, ca: fs.readFileSync(process.env.PGSSLROOTCERT, 'utf8'), servername: process.env.PGHOST },
    max: 2, connectionTimeoutMillis: 3000, query_timeout: 5000, statement_timeout: 5000,
    idleTimeoutMillis: 10000, application_name: 'sky-tug-game' });
  pool.on('error', () => { /* No DSN, password or raw driver error in logs. */ });
  // A standby may start before its first snapshot copy. Liveness is not DB
  // readiness; the controller's probe must read the real schema before resume.
  return {
    async saveRound(r) {
      await pool.query('INSERT INTO public.rounds (started_at,ended_at,winner,taps_a,taps_b,players_a,players_b) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [r.startedAt, r.endedAt, r.winner, r.taps.A, r.taps.B, r.players.A, r.players.B]);
    },
    async recentRounds(limit = 10) {
      limit = Number.isFinite(limit) ? Math.max(1, Math.min(100, Math.trunc(limit))) : 10;
      const { rows } = await pool.query('SELECT id,started_at,ended_at,winner,taps_a,taps_b,players_a,players_b FROM public.rounds ORDER BY id DESC LIMIT $1', [limit]);
      return rows.map(r => ({ id: Number(r.id), startedAt: Number(r.started_at), endedAt: Number(r.ended_at),
        winner: r.winner, taps: { A: Number(r.taps_a), B: Number(r.taps_b) },
        players: { A: Number(r.players_a), B: Number(r.players_b) } }));
    },
    async summary() {
      const { rows: [r] } = await pool.query("SELECT COUNT(*)::int AS rounds, COUNT(*) FILTER (WHERE winner='A')::int AS wins_a, COUNT(*) FILTER (WHERE winner='B')::int AS wins_b, COUNT(*) FILTER (WHERE winner='DRAW')::int AS draws, COALESCE(SUM(taps_a+taps_b),0) AS taps, COALESCE(MAX(taps_a+taps_b),0) AS best FROM public.rounds");
      return { rounds: r.rounds, wins: { A: r.wins_a, B: r.wins_b }, draws: r.draws,
        totalTaps: Number(r.taps), bestRoundTaps: Number(r.best) };
    },
    async close() { await pool.end(); },
  };
}
module.exports = { openScores, available: () => true };
