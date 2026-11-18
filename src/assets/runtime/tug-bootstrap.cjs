'use strict';
// Fixed deployment bootstrap. Private files live in /dev/shm on a read-only root.
const fs = require('node:fs');
const path = require('node:path');
let config;
try {
  const raw = process.env.SKY_GAME_CONFIG_FILE ? fs.readFileSync(process.env.SKY_GAME_CONFIG_FILE, 'utf8') : process.env.SKY_GAME_CONFIG;
  config = JSON.parse(raw);
  if (!config || !config.database || !config.server_key || !config.server_cert || !config.database_ca || !config.control_ca) throw new Error();
} catch { throw new Error('Registered private game configuration required'); }
delete process.env.SKY_GAME_CONFIG;
const root = fs.mkdtempSync('/dev/shm/sky-game-');
fs.chmodSync(root, 0o700);
const put = (name, data) => { const file = path.join(root, name); fs.writeFileSync(file, data, { mode: 0o600, flag: 'wx' }); return file; };
config.tls_key = put('server.key', config.server_key); config.tls_cert = put('server.pem', config.server_cert);
config.ca_file = put('control-ca.pem', config.control_ca);
delete config.server_key; delete config.server_cert; delete config.control_ca;
const ca = put('database-ca.pem', config.database_ca); delete config.database_ca;
const db = config.database;
for (const [key, value] of Object.entries({ PGHOST: db.host, PGPORT: db.port, PGUSER: db.user,
  PGPASSWORD: db.password, PGDATABASE: db.dbname, PGSSLROOTCERT: ca, PGSSLMODE: 'verify-full' })) {
  if (value === undefined) throw new Error('Incomplete game database settings');
  process.env[key] = String(value);
}
delete config.database;
process.env.SKY_GAME_MIGRATION_CONFIG = put('controller.json', JSON.stringify(config));
const app = require('./server').createTugServer();
app.on('error', () => { console.error('Game listener unavailable'); process.exitCode = 1; });
app.listen(Number(process.env.PORT || 8443), '0.0.0.0');
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  app.closeAll().then(() => { fs.rmSync(root, { recursive: true }); process.exit(0); }, () => process.exit(1));
  setTimeout(() => process.exit(1), 5000).unref();
});
