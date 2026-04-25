/**
 * database.js
 *
 * Dual-mode database layer:
 *   • PRODUCTION  — Turso (hosted LibSQL) when TURSO_URL + TURSO_TOKEN are set
 *   • LOCAL DEV   — sql.js (pure-WASM SQLite) stored in tracker.db
 *
 * Synchronous existence checks (deviceExists / networkExists / fingerprintExists)
 * work via in-memory Sets that are warmed at startup and updated on every write.
 * This keeps the correlation classifier synchronous while the underlying DB is async.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ─── Mode ─────────────────────────────────────────────────────────────────────
const TURSO_URL   = process.env.TURSO_URL;
const TURSO_TOKEN = process.env.TURSO_TOKEN;
const USE_TURSO   = !!(TURSO_URL && TURSO_TOKEN);

// In-memory caches for SYNC existence checks (warmed at startup)
const deviceCache  = new Set();   // known device_ids
const networkCache = new Set();   // known network_ids
const fpCache      = new Set();   // known fingerprint_ids

let db;     // sql.js Database instance
let turso;  // @libsql/client instance

// ─── Schema ───────────────────────────────────────────────────────────────────
const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS networks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id    TEXT    NOT NULL UNIQUE,
    ip            TEXT    NOT NULL,
    isp           TEXT,
    country       TEXT,
    region        TEXT,
    city          TEXT,
    label         TEXT,
    first_seen    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    visit_count   INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS devices (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id         TEXT NOT NULL UNIQUE,
    fingerprint_id    TEXT,
    user_agent        TEXT,
    browser           TEXT,
    browser_version   TEXT,
    os                TEXT,
    os_version        TEXT,
    device_type       TEXT,
    screen_resolution TEXT,
    color_depth       INTEGER,
    timezone          TEXT,
    language          TEXT,
    platform          TEXT,
    cpu_cores         INTEGER,
    memory_gb         REAL,
    touch_support     INTEGER DEFAULT 0,
    last_ip           TEXT,
    last_isp          TEXT,
    last_city         TEXT,
    first_seen        TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen         TEXT NOT NULL DEFAULT (datetime('now')),
    visit_count       INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS visits (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_time     TEXT NOT NULL DEFAULT (datetime('now')),
    device_id      TEXT NOT NULL,
    network_id     TEXT NOT NULL,
    fingerprint_id TEXT,
    correlation    TEXT NOT NULL,
    risk_score     INTEGER DEFAULT 0,
    risk_factors   TEXT,
    raw_data       TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_visits_device  ON visits(device_id)`,
  `CREATE INDEX IF NOT EXISTS idx_visits_network ON visits(network_id)`,
  `CREATE INDEX IF NOT EXISTS idx_visits_time    ON visits(visit_time)`,
  `CREATE INDEX IF NOT EXISTS idx_visits_fp      ON visits(fingerprint_id)`,
  `CREATE INDEX IF NOT EXISTS idx_devices_fp     ON devices(fingerprint_id)`,
  `CREATE TABLE IF NOT EXISTS payment_methods (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT    NOT NULL,
    last4       TEXT    NOT NULL,
    bin         TEXT,
    bin8        TEXT,
    device_id   TEXT    NOT NULL,
    first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(token, device_id)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_pm_token     ON payment_methods(token)`,
  `CREATE INDEX IF NOT EXISTS idx_pm_device_id ON payment_methods(device_id)`,
  `CREATE TABLE IF NOT EXISTS bin_cache (
    bin6       TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS kyc_applications (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id         TEXT NOT NULL,
    veriff_session_id TEXT UNIQUE,
    status            TEXT NOT NULL DEFAULT 'NOT_STARTED',
    first_name        TEXT,
    last_name         TEXT,
    dob               TEXT,
    id_type           TEXT DEFAULT 'ID_CARD',
    address_line1     TEXT,
    address_city      TEXT,
    address_postcode  TEXT,
    address_status    TEXT NOT NULL DEFAULT 'NOT_SUBMITTED',
    veriff_decision   TEXT,
    veriff_code       INTEGER,
    veriff_person     TEXT,
    decline_reason    TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    decision_at       TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_kyc_device    ON kyc_applications(device_id)`,
  `CREATE INDEX IF NOT EXISTS idx_kyc_session   ON kyc_applications(veriff_session_id)`,
  `CREATE INDEX IF NOT EXISTS idx_kyc_status    ON kyc_applications(status)`,
  /* ── Manual KYC review table ── */
  `CREATE TABLE IF NOT EXISTS kyc_manual (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL,
    first_name      TEXT NOT NULL,
    last_name       TEXT NOT NULL,
    dob             TEXT NOT NULL,
    adt             TEXT,
    afm             TEXT,
    amka            TEXT,
    id_front        TEXT,
    id_back         TEXT,
    selfie          TEXT,
    validations     TEXT,
    status          TEXT NOT NULL DEFAULT 'PENDING',
    operator_notes  TEXT,
    reviewed_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_kyc_manual_device ON kyc_manual(device_id)`,
  `CREATE INDEX IF NOT EXISTS idx_kyc_manual_status ON kyc_manual(status)`,
  `CREATE INDEX IF NOT EXISTS idx_kyc_manual_adt    ON kyc_manual(adt)`,
  `CREATE INDEX IF NOT EXISTS idx_kyc_manual_afm    ON kyc_manual(afm)`,
];

// Safe migrations — add new columns AND dependent indexes (all fail silently if already present)
const MIGRATIONS = [
  `ALTER TABLE devices ADD COLUMN last_ip      TEXT`,
  `ALTER TABLE devices ADD COLUMN last_isp     TEXT`,
  `ALTER TABLE devices ADD COLUMN last_city    TEXT`,
  // indexes on columns added above — must come AFTER the ALTER TABLEs
  `CREATE INDEX IF NOT EXISTS idx_devices_city ON devices(last_city)`,
  `CREATE INDEX IF NOT EXISTS idx_devices_isp  ON devices(last_isp)`,
  `ALTER TABLE devices ADD COLUMN device_name  TEXT`,
  `ALTER TABLE visits  ADD COLUMN risk_score   INTEGER DEFAULT 0`,
  `ALTER TABLE visits  ADD COLUMN risk_factors TEXT`,
  `ALTER TABLE payment_methods ADD COLUMN bin8 TEXT`,
  // index on bin8 — must come AFTER the ALTER TABLE above
  `CREATE INDEX IF NOT EXISTS idx_pm_bin8 ON payment_methods(bin8)`,
  // LAN / local-network scanning signals
  `ALTER TABLE visits ADD COLUMN lan_peers TEXT`,
  `ALTER TABLE visits ADD COLUMN local_ip  TEXT`,
];

// ─── sql.js helpers ───────────────────────────────────────────────────────────
const DB_PATH = path.join(__dirname, 'tracker.db');

function persistDB() {
  if (db) fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function sqlRun(sql, params = []) {
  db.run(sql, params);
  persistDB();
}

function sqlGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) { const r = stmt.getAsObject(); stmt.free(); return r; }
  stmt.free();
  return undefined;
}

function sqlAll(sql, params = []) {
  const rows = [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ─── Turso helpers ────────────────────────────────────────────────────────────
function tursoRows(rs) {
  return rs.rows.map(r => {
    const obj = {};
    rs.columns.forEach((col, i) => { obj[col] = r[i]; });
    return obj;
  });
}

function tursoFirst(rs) {
  if (!rs.rows.length) return undefined;
  const obj = {};
  rs.columns.forEach((col, i) => { obj[col] = rs.rows[0][i]; });
  return obj;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
async function initDB() {
  if (USE_TURSO) {
    const { createClient } = require('@libsql/client');
    turso = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

    // Create tables + indexes (fail silently on pre-existing objects)
    for (const stmt of SCHEMA_STATEMENTS) {
      try { await turso.execute(stmt); } catch (_) { /* table/index already exists */ }
    }

    // Safe column migrations + dependent indexes (all fail silently if already present)
    for (const m of MIGRATIONS) {
      try { await turso.execute(m); } catch (_) { /* already exists */ }
    }

    // Warm in-memory caches
    const [devRS, netRS, fpRS] = await Promise.all([
      turso.execute('SELECT device_id FROM devices'),
      turso.execute('SELECT network_id FROM networks'),
      turso.execute('SELECT fingerprint_id FROM devices WHERE fingerprint_id IS NOT NULL'),
    ]);
    tursoRows(devRS).forEach(r => deviceCache.add(r.device_id));
    tursoRows(netRS).forEach(r => networkCache.add(r.network_id));
    tursoRows(fpRS).forEach(r => fpCache.add(r.fingerprint_id));

    console.log(`[DB] Turso connected — ${deviceCache.size} devices, ${networkCache.size} networks`);
  } else {
    const initSqlJs = require('sql.js');
    const SQL = await initSqlJs();
    if (fs.existsSync(DB_PATH)) {
      db = new SQL.Database(fs.readFileSync(DB_PATH));
    } else {
      db = new SQL.Database();
    }

    // Create tables (sql.js supports multi-statement run via join)
    db.run(SCHEMA_STATEMENTS.join(';\n'));
    persistDB();

    // Safe column migrations
    for (const m of MIGRATIONS) {
      try { db.run(m); persistDB(); } catch (_) { /* already exists */ }
    }

    // Warm in-memory caches
    sqlAll('SELECT device_id FROM devices').forEach(r => deviceCache.add(r.device_id));
    sqlAll('SELECT network_id FROM networks').forEach(r => networkCache.add(r.network_id));
    sqlAll('SELECT fingerprint_id FROM devices WHERE fingerprint_id IS NOT NULL')
      .forEach(r => fpCache.add(r.fingerprint_id));

    console.log(`[DB] sql.js initialised — ${deviceCache.size} devices, ${networkCache.size} networks → ${DB_PATH}`);
  }
}

// ─── Upsert helpers ───────────────────────────────────────────────────────────

async function upsertNetwork(data) {
  networkCache.add(data.network_id);

  if (USE_TURSO) {
    await turso.execute({
      sql: `INSERT INTO networks (network_id, ip, isp, country, region, city, visit_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(network_id) DO UPDATE SET
              ip          = excluded.ip,
              last_seen   = datetime('now'),
              visit_count = visit_count + 1`,
      args: [data.network_id, data.ip, data.isp||null, data.country||null, data.region||null, data.city||null],
    });
  } else {
    const existing = sqlGet('SELECT id FROM networks WHERE network_id = ?', [data.network_id]);
    if (existing) {
      sqlRun(`UPDATE networks SET ip=?, last_seen=datetime('now'), visit_count=visit_count+1 WHERE network_id=?`,
        [data.ip, data.network_id]);
    } else {
      sqlRun(`INSERT INTO networks (network_id,ip,isp,country,region,city,visit_count) VALUES (?,?,?,?,?,?,1)`,
        [data.network_id, data.ip, data.isp||null, data.country||null, data.region||null, data.city||null]);
    }
  }
}

async function upsertDevice(data) {
  deviceCache.add(data.device_id);
  if (data.fingerprint_id) fpCache.add(data.fingerprint_id);

  if (USE_TURSO) {
    await turso.execute({
      sql: `INSERT INTO devices
              (device_id, fingerprint_id, user_agent, browser, browser_version,
               os, os_version, device_type, screen_resolution, color_depth,
               timezone, language, platform, cpu_cores, memory_gb, touch_support,
               last_ip, last_isp, last_city, visit_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
            ON CONFLICT(device_id) DO UPDATE SET
              fingerprint_id    = COALESCE(excluded.fingerprint_id, fingerprint_id),
              user_agent        = excluded.user_agent,
              browser           = excluded.browser,
              browser_version   = excluded.browser_version,
              os                = excluded.os,
              os_version        = excluded.os_version,
              device_type       = excluded.device_type,
              screen_resolution = excluded.screen_resolution,
              color_depth       = excluded.color_depth,
              timezone          = excluded.timezone,
              language          = excluded.language,
              platform          = excluded.platform,
              cpu_cores         = excluded.cpu_cores,
              memory_gb         = excluded.memory_gb,
              touch_support     = excluded.touch_support,
              last_ip           = excluded.last_ip,
              last_isp          = excluded.last_isp,
              last_city         = excluded.last_city,
              last_seen         = datetime('now'),
              visit_count       = visit_count + 1`,
      args: [
        data.device_id,
        data.fingerprint_id    || null,
        data.user_agent        || null,
        data.browser           || null,
        data.browser_version   || null,
        data.os                || null,
        data.os_version        || null,
        data.device_type       || null,
        data.screen_resolution || null,
        data.color_depth       || null,
        data.timezone          || null,
        data.language          || null,
        data.platform          || null,
        data.cpu_cores         || null,
        data.memory_gb         || null,
        data.touch_support     ? 1 : 0,
        data.last_ip           || null,
        data.last_isp          || null,
        data.last_city         || null,
      ],
    });
  } else {
    const existing = sqlGet('SELECT id FROM devices WHERE device_id = ?', [data.device_id]);
    if (existing) {
      sqlRun(`
        UPDATE devices SET
          fingerprint_id=COALESCE(?,fingerprint_id), user_agent=?, browser=?,
          browser_version=?, os=?, os_version=?, device_type=?,
          screen_resolution=?, color_depth=?, timezone=?, language=?,
          platform=?, cpu_cores=?, memory_gb=?, touch_support=?,
          last_ip=?, last_isp=?, last_city=?,
          last_seen=datetime('now'), visit_count=visit_count+1
        WHERE device_id=?
      `, [
        data.fingerprint_id||null, data.user_agent||null, data.browser||null,
        data.browser_version||null, data.os||null, data.os_version||null,
        data.device_type||null, data.screen_resolution||null, data.color_depth||null,
        data.timezone||null, data.language||null, data.platform||null,
        data.cpu_cores||null, data.memory_gb||null, data.touch_support?1:0,
        data.last_ip||null, data.last_isp||null, data.last_city||null,
        data.device_id,
      ]);
    } else {
      sqlRun(`
        INSERT INTO devices
          (device_id,fingerprint_id,user_agent,browser,browser_version,
           os,os_version,device_type,screen_resolution,color_depth,
           timezone,language,platform,cpu_cores,memory_gb,touch_support,
           last_ip,last_isp,last_city,visit_count)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
      `, [
        data.device_id, data.fingerprint_id||null, data.user_agent||null,
        data.browser||null, data.browser_version||null, data.os||null,
        data.os_version||null, data.device_type||null, data.screen_resolution||null,
        data.color_depth||null, data.timezone||null, data.language||null,
        data.platform||null, data.cpu_cores||null, data.memory_gb||null,
        data.touch_support?1:0, data.last_ip||null, data.last_isp||null,
        data.last_city||null,
      ]);
    }
  }
}

async function insertVisit(data) {
  if (USE_TURSO) {
    await turso.execute({
      sql: `INSERT INTO visits (device_id,network_id,fingerprint_id,correlation,risk_score,risk_factors,raw_data,lan_peers,local_ip)
            VALUES (?,?,?,?,?,?,?,?,?)`,
      args: [
        data.device_id,
        data.network_id,
        data.fingerprint_id || null,
        data.correlation,
        data.risk_score     || 0,
        data.risk_factors   || null,
        JSON.stringify(data.raw_data),
        data.lan_peers      || null,
        data.local_ip       || null,
      ],
    });
  } else {
    sqlRun(`
      INSERT INTO visits (device_id,network_id,fingerprint_id,correlation,risk_score,risk_factors,raw_data,lan_peers,local_ip)
      VALUES (?,?,?,?,?,?,?,?,?)
    `, [
      data.device_id,
      data.network_id,
      data.fingerprint_id || null,
      data.correlation,
      data.risk_score     || 0,
      data.risk_factors   || null,
      JSON.stringify(data.raw_data),
      data.lan_peers      || null,
      data.local_ip       || null,
    ]);
  }
}

// ─── LAN correlation — find other devices sharing local-network peers ─────────
async function getLanCorrelations(device_id, lan_peers_json) {
  if (!lan_peers_json) return [];
  let myPeers;
  try { myPeers = JSON.parse(lan_peers_json); } catch(_) { return []; }
  if (!Array.isArray(myPeers) || myPeers.length === 0) return [];

  // Pull the most-recent LAN scan per distinct device (exclude current)
  const sql = `
    SELECT v.device_id, d.device_name, v.lan_peers
    FROM visits v
    LEFT JOIN devices d ON d.device_id = v.device_id
    WHERE v.lan_peers IS NOT NULL
      AND v.device_id != ?
    GROUP BY v.device_id
    ORDER BY MAX(v.visited_at) DESC
    LIMIT 200
  `;

  let rows = [];
  try {
    if (USE_TURSO) {
      const rs = await turso.execute({ sql, args: [device_id] });
      rows = tursoRows(rs);
    } else {
      rows = sqlAll(sql, [device_id]);
    }
  } catch(_) { return []; }

  const results = [];
  for (const row of rows) {
    try {
      const theirPeers = JSON.parse(row.lan_peers || '[]');
      const shared = myPeers.filter(ip => theirPeers.includes(ip));
      // Require at least 2 shared IPs AND > 30% overlap to avoid random collisions
      const overlapPct = shared.length / Math.max(myPeers.length, theirPeers.length);
      if (shared.length >= 2 && overlapPct >= 0.30) {
        results.push({
          device_id:    row.device_id,
          device_name:  row.device_name || null,
          shared_count: shared.length,
          my_total:     myPeers.length,
          their_total:  theirPeers.length,
        });
      }
    } catch(_) {}
  }

  return results.sort((a, b) => b.shared_count - a.shared_count);
}

// ─── Sync existence checks (correlation classifier) ───────────────────────────
function deviceExists(device_id)      { return deviceCache.has(device_id);      }
function networkExists(network_id)    { return networkCache.has(network_id);     }
function fingerprintExists(fp_id)     { return fpCache.has(fp_id);               }

// ─── Similarity queries (called async BEFORE classify()) ─────────────────────

/**
 * Return known device records last seen from the same city or ISP.
 * Excludes the current device_id (so we don't compare it to itself).
 */
async function getSimilarDevices(city, isp, excludeDeviceId = null) {
  if (!city && !isp) return [];

  const sql = `
    SELECT device_id, screen_resolution, timezone, browser, os,
           language, cpu_cores, memory_gb, platform, last_ip, last_isp, last_city
    FROM devices
    WHERE (last_city = ? OR last_isp = ?)
      AND (? IS NULL OR device_id != ?)
    LIMIT 100
  `;

  if (USE_TURSO) {
    const rs = await turso.execute({
      sql,
      args: [city||null, isp||null, excludeDeviceId||null, excludeDeviceId||null],
    });
    return tursoRows(rs);
  } else {
    return sqlAll(sql, [city||null, isp||null, excludeDeviceId||null, excludeDeviceId||null]);
  }
}

/**
 * Return networks this fingerprint was seen from in the past N hours.
 */
async function getRecentNetworksForFingerprint(fingerprint_id, hoursBack = 4) {
  if (!fingerprint_id) return [];

  const cutoff = new Date(Date.now() - hoursBack * 3600 * 1000)
    .toISOString().replace('T', ' ').slice(0, 19);

  const sql = `
    SELECT DISTINCT v.network_id, n.isp, n.city, n.ip
    FROM   visits   v
    JOIN   networks n ON n.network_id = v.network_id
    WHERE  v.fingerprint_id = ?
      AND  v.visit_time >= ?
  `;

  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args: [fingerprint_id, cutoff] });
    return tursoRows(rs);
  } else {
    return sqlAll(sql, [fingerprint_id, cutoff]);
  }
}

// ─── History / summary queries ────────────────────────────────────────────────

async function getRecentVisits(limit = 50) {
  const sql = `
    SELECT
      v.id, v.visit_time, v.correlation, v.risk_score,
      v.device_id, v.network_id,
      d.browser, d.browser_version, d.os, d.os_version,
      d.device_type, d.screen_resolution, d.timezone,
      d.visit_count AS device_visits,
      n.ip, n.isp, n.city, n.country,
      n.visit_count AS network_visits,
      n.label AS network_label
    FROM   visits   v
    LEFT JOIN devices  d ON d.device_id  = v.device_id
    LEFT JOIN networks n ON n.network_id = v.network_id
    ORDER BY v.visit_time DESC
    LIMIT ?
  `;

  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args: [limit] });
    return tursoRows(rs);
  } else {
    return sqlAll(sql, [limit]);
  }
}

async function getDeviceSummaries() {
  const sql = `
    SELECT d.*, COUNT(v.id) AS total_visits, MAX(v.visit_time) AS last_visit
    FROM   devices d
    LEFT JOIN visits v ON v.device_id = d.device_id
    GROUP BY d.device_id
    ORDER BY d.last_seen DESC
  `;

  if (USE_TURSO) {
    const rs = await turso.execute(sql);
    return tursoRows(rs);
  } else {
    return sqlAll(sql);
  }
}

async function getNetworkSummaries() {
  const sql = `
    SELECT n.*, COUNT(v.id) AS total_visits,
           COUNT(DISTINCT v.device_id) AS unique_devices,
           MAX(v.visit_time) AS last_visit
    FROM   networks n
    LEFT JOIN visits v ON v.network_id = n.network_id
    GROUP BY n.network_id
    ORDER BY n.last_seen DESC
  `;

  if (USE_TURSO) {
    const rs = await turso.execute(sql);
    return tursoRows(rs);
  } else {
    return sqlAll(sql);
  }
}

async function getStats() {
  const sql = `
    SELECT
      (SELECT COUNT(*) FROM visits)                            AS total_visits,
      (SELECT COUNT(*) FROM devices)                           AS total_devices,
      (SELECT COUNT(*) FROM networks)                          AS total_networks,
      (SELECT COUNT(*) FROM visits WHERE correlation='GREEN')  AS green_count,
      (SELECT COUNT(*) FROM visits WHERE correlation='YELLOW') AS yellow_count,
      (SELECT COUNT(*) FROM visits WHERE correlation='BLUE')   AS blue_count,
      (SELECT COUNT(*) FROM visits WHERE correlation='ORANGE') AS orange_count,
      (SELECT COUNT(*) FROM visits WHERE correlation='RED')    AS red_count
  `;

  if (USE_TURSO) {
    const rs = await turso.execute(sql);
    return tursoFirst(rs);
  } else {
    return sqlGet(sql);
  }
}

// ─── Payment methods ──────────────────────────────────────────────────────────

/**
 * Store a card token (SHA-256 of the raw card number) linked to a device.
 * Returns { isNew, matchingDevices } where matchingDevices are OTHER device_ids
 * that previously used the same card token.
 */
async function upsertPaymentMethod({ token, last4, bin, bin8, device_id }) {
  let isNew = true;

  if (USE_TURSO) {
    // Check if this device already has this token
    const existRS = await turso.execute({
      sql:  'SELECT id FROM payment_methods WHERE token = ? AND device_id = ?',
      args: [token, device_id],
    });
    isNew = existRS.rows.length === 0;

    await turso.execute({
      sql: `INSERT INTO payment_methods (token, last4, bin, bin8, device_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(token, device_id) DO UPDATE SET last_seen = datetime('now')`,
      args: [token, last4, bin || null, bin8 || null, device_id],
    });

    // Devices (excluding current) that have used the same token
    const matchRS = await turso.execute({
      sql: `SELECT pm.device_id, pm.last4, pm.first_seen, pm.last_seen,
                   d.browser, d.os, d.last_ip, d.last_city, d.last_isp
            FROM payment_methods pm
            LEFT JOIN devices d ON d.device_id = pm.device_id
            WHERE pm.token = ? AND pm.device_id != ?
            ORDER BY pm.last_seen DESC`,
      args: [token, device_id],
    });
    return { isNew, matchingDevices: tursoRows(matchRS) };

  } else {
    const existing = sqlGet('SELECT id FROM payment_methods WHERE token = ? AND device_id = ?', [token, device_id]);
    isNew = !existing;

    if (existing) {
      sqlRun(`UPDATE payment_methods SET last_seen = datetime('now') WHERE token = ? AND device_id = ?`,
        [token, device_id]);
    } else {
      sqlRun(`INSERT INTO payment_methods (token, last4, bin, bin8, device_id) VALUES (?, ?, ?, ?, ?)`,
        [token, last4, bin || null, bin8 || null, device_id]);
    }

    const matchingDevices = sqlAll(
      `SELECT pm.device_id, pm.last4, pm.first_seen, pm.last_seen,
              d.browser, d.os, d.last_ip, d.last_city, d.last_isp
       FROM payment_methods pm
       LEFT JOIN devices d ON d.device_id = pm.device_id
       WHERE pm.token = ? AND pm.device_id != ?
       ORDER BY pm.last_seen DESC`,
      [token, device_id],
    );
    return { isNew, matchingDevices };
  }
}

/**
 * Get all devices linked to a given device via:
 *   paymentLinks  — shared card token
 *   fingerprintLinks — shared fingerprint_id
 *   ipLinks       — same /24 IP subnet
 */
async function getGraphLinks({ device_id, fingerprint_id, ip }) {
  let paymentLinks = [], binLinks = [], fingerprintLinks = [], ipLinks = [];

  if (USE_TURSO) {
    // Exact card matches (same token, different device)
    const pmRS = await turso.execute({
      sql: `SELECT pm2.device_id, pm2.last4, pm2.bin8, pm2.last_seen,
                   d.browser, d.os, d.last_ip, d.last_city, d.last_isp, d.visit_count
            FROM payment_methods pm
            JOIN payment_methods pm2 ON pm2.token = pm.token AND pm2.device_id != pm.device_id
            LEFT JOIN devices d ON d.device_id = pm2.device_id
            WHERE pm.device_id = ?
            ORDER BY pm2.last_seen DESC`,
      args: [device_id],
    });
    paymentLinks = tursoRows(pmRS);

    // BIN8 issuer matches (same card provider, different card & device)
    // Only show if this device has at least one payment registered
    const myBinsRS = await turso.execute({
      sql: `SELECT DISTINCT bin8 FROM payment_methods WHERE device_id = ? AND bin8 IS NOT NULL`,
      args: [device_id],
    });
    const myBins = tursoRows(myBinsRS).map(r => r.bin8);

    for (const bin8 of myBins) {
      const binRS = await turso.execute({
        sql: `SELECT DISTINCT pm.device_id, pm.last4, pm.bin8, pm.last_seen,
                     d.browser, d.os, d.last_ip, d.last_city, d.last_isp, d.visit_count
              FROM payment_methods pm
              LEFT JOIN devices d ON d.device_id = pm.device_id
              WHERE pm.bin8 = ?
                AND pm.device_id != ?
                AND pm.token NOT IN (
                  SELECT token FROM payment_methods WHERE device_id = ?
                )
              ORDER BY pm.last_seen DESC
              LIMIT 50`,
        args: [bin8, device_id, device_id],
      });
      const rows = tursoRows(binRS);
      // Deduplicate by device_id (a device might have multiple cards from same issuer)
      const seen = new Set(binLinks.map(r => r.device_id));
      for (const r of rows) {
        if (!seen.has(r.device_id)) { binLinks.push(r); seen.add(r.device_id); }
      }
    }

    // Fingerprint links
    if (fingerprint_id) {
      const fpRS = await turso.execute({
        sql: `SELECT d.device_id, d.browser, d.os, d.last_ip, d.last_city, d.last_isp,
                     d.visit_count, d.last_seen
              FROM devices d
              WHERE d.fingerprint_id = ? AND d.device_id != ?
              ORDER BY d.last_seen DESC`,
        args: [fingerprint_id, device_id],
      });
      fingerprintLinks = tursoRows(fpRS);
    }

    // IP subnet links (/24 — same first 3 octets)
    if (ip) {
      const subnet = ip.split('.').slice(0, 3).join('.') + '.';
      const ipRS = await turso.execute({
        sql: `SELECT DISTINCT d.device_id, d.browser, d.os, d.last_ip, d.last_city, d.last_isp,
                     d.visit_count, d.last_seen
              FROM devices d
              WHERE d.last_ip LIKE ? AND d.device_id != ?
              ORDER BY d.last_seen DESC
              LIMIT 50`,
        args: [subnet + '%', device_id],
      });
      ipLinks = tursoRows(ipRS);
    }

  } else {
    // Exact card matches
    paymentLinks = sqlAll(
      `SELECT pm2.device_id, pm2.last4, pm2.bin8, pm2.last_seen,
              d.browser, d.os, d.last_ip, d.last_city, d.last_isp, d.visit_count
       FROM payment_methods pm
       JOIN payment_methods pm2 ON pm2.token = pm.token AND pm2.device_id != pm.device_id
       LEFT JOIN devices d ON d.device_id = pm2.device_id
       WHERE pm.device_id = ?
       ORDER BY pm2.last_seen DESC`,
      [device_id],
    );

    // BIN8 issuer matches
    const myBins = sqlAll(
      `SELECT DISTINCT bin8 FROM payment_methods WHERE device_id = ? AND bin8 IS NOT NULL`,
      [device_id],
    ).map(r => r.bin8);

    for (const bin8 of myBins) {
      const rows = sqlAll(
        `SELECT DISTINCT pm.device_id, pm.last4, pm.bin8, pm.last_seen,
                d.browser, d.os, d.last_ip, d.last_city, d.last_isp, d.visit_count
         FROM payment_methods pm
         LEFT JOIN devices d ON d.device_id = pm.device_id
         WHERE pm.bin8 = ?
           AND pm.device_id != ?
           AND pm.token NOT IN (
             SELECT token FROM payment_methods WHERE device_id = ?
           )
         ORDER BY pm.last_seen DESC
         LIMIT 50`,
        [bin8, device_id, device_id],
      );
      const seen = new Set(binLinks.map(r => r.device_id));
      for (const r of rows) {
        if (!seen.has(r.device_id)) { binLinks.push(r); seen.add(r.device_id); }
      }
    }

    // Fingerprint links
    if (fingerprint_id) {
      fingerprintLinks = sqlAll(
        `SELECT d.device_id, d.browser, d.os, d.last_ip, d.last_city, d.last_isp,
                d.visit_count, d.last_seen
         FROM devices d
         WHERE d.fingerprint_id = ? AND d.device_id != ?
         ORDER BY d.last_seen DESC`,
        [fingerprint_id, device_id],
      );
    }

    // IP subnet links
    if (ip) {
      const subnet = ip.split('.').slice(0, 3).join('.') + '.';
      ipLinks = sqlAll(
        `SELECT DISTINCT d.device_id, d.browser, d.os, d.last_ip, d.last_city, d.last_isp,
                d.visit_count, d.last_seen
         FROM devices d
         WHERE d.last_ip LIKE ? AND d.device_id != ?
         ORDER BY d.last_seen DESC
         LIMIT 50`,
        [subnet + '%', device_id],
      );
    }
  }

  return { paymentLinks, binLinks, fingerprintLinks, ipLinks };
}

// ─── BIN cache ────────────────────────────────────────────────────────────────

async function getBINCache(bin6) {
  const sql = `SELECT data FROM bin_cache WHERE bin6 = ?`;
  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args: [bin6] });
    const row = tursoFirst(rs);
    return row ? JSON.parse(row.data) : null;
  } else {
    const row = sqlGet(sql, [bin6]);
    return row ? JSON.parse(row.data) : null;
  }
}

async function setBINCache(bin6, data) {
  if (USE_TURSO) {
    await turso.execute({
      sql:  `INSERT INTO bin_cache (bin6, data) VALUES (?, ?) ON CONFLICT(bin6) DO UPDATE SET data=excluded.data, fetched_at=datetime('now')`,
      args: [bin6, JSON.stringify(data)],
    });
  } else {
    const existing = sqlGet('SELECT bin6 FROM bin_cache WHERE bin6 = ?', [bin6]);
    if (existing) {
      sqlRun(`UPDATE bin_cache SET data=?, fetched_at=datetime('now') WHERE bin6=?`, [JSON.stringify(data), bin6]);
    } else {
      sqlRun(`INSERT INTO bin_cache (bin6, data) VALUES (?, ?)`, [bin6, JSON.stringify(data)]);
    }
  }
}

// ─── Device detail helper (used by cluster BFS) ───────────────────────────────

async function getDeviceDetails(device_id) {
  const sql = `SELECT device_id, fingerprint_id, last_ip, last_isp, last_city, browser, os, visit_count, last_seen, device_name
               FROM devices WHERE device_id = ?`;
  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args: [device_id] });
    return tursoFirst(rs) || null;
  } else {
    return sqlGet(sql, [device_id]) || null;
  }
}

// ─── Cluster BFS ──────────────────────────────────────────────────────────────
/**
 * Walk the entire connected component starting from start_device_id.
 * Traverses through payment token matches, BIN8 matches, fingerprint matches
 * and IP-subnet matches up to maxDevices total.
 *
 * Returns { clusterSize, devices: [...], edges: [{from,to,type,detail}] }
 */
async function getDeviceCluster(start_device_id, { maxDevices = 60 } = {}) {
  const visited = new Set([start_device_id]);
  const queue   = [start_device_id];
  const edges   = [];                    // deduplicated edge list
  const edgeSet = new Set();             // "A|B|type" for dedup
  const deviceMap = {};                  // device_id → details

  function addEdge(from, to, type, detail) {
    const key = [from, to, type].join('|');
    const rev = [to, from, type].join('|');
    if (edgeSet.has(key) || edgeSet.has(rev)) return;
    edgeSet.add(key);
    edges.push({ from, to, type, detail: detail || '' });
  }

  while (queue.length > 0 && visited.size < maxDevices) {
    const current = queue.shift();

    // Fetch device info so we can run all link types
    const info = await getDeviceDetails(current);
    if (info) deviceMap[current] = info;

    const { paymentLinks, binLinks, fingerprintLinks, ipLinks } = await getGraphLinks({
      device_id:      current,
      fingerprint_id: info?.fingerprint_id || null,
      ip:             info?.last_ip        || null,
    });

    const allLinks = [
      ...paymentLinks.map(d => ({ ...d, _type: 'payment',     _detail: `Card ••••${d.last4}` })),
      ...binLinks.map(d =>     ({ ...d, _type: 'bin',         _detail: `BIN ${d.bin8 || ''}` })),
      ...fingerprintLinks.map(d => ({ ...d, _type: 'fingerprint', _detail: 'Same fingerprint' })),
      ...ipLinks.map(d =>      ({ ...d, _type: 'ip',          _detail: `IP ${d.last_ip}` })),
    ];

    for (const linked of allLinks) {
      if (!linked.device_id) continue;
      addEdge(current, linked.device_id, linked._type, linked._detail);

      if (!visited.has(linked.device_id) && visited.size < maxDevices) {
        visited.add(linked.device_id);
        queue.push(linked.device_id);
        // Store raw device data we already have from the link query
        if (!deviceMap[linked.device_id]) {
          deviceMap[linked.device_id] = {
            device_id:  linked.device_id,
            browser:    linked.browser,
            os:         linked.os,
            last_ip:    linked.last_ip,
            last_city:  linked.last_city,
            last_isp:   linked.last_isp,
            visit_count: linked.visit_count,
            last_seen:  linked.last_seen,
          };
        }
      }
    }
  }

  return {
    clusterSize: visited.size,
    devices: Object.values(deviceMap),
    edges,
    truncated: visited.size >= maxDevices,
  };
}

// ─── KYC ─────────────────────────────────────────────────────────────────────

/**
 * Get current KYC application for a device (or null).
 */
async function getKYCApplication(device_id) {
  const sql = `SELECT * FROM kyc_applications WHERE device_id = ? ORDER BY id DESC LIMIT 1`;
  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args: [device_id] });
    return tursoFirst(rs) || null;
  } else {
    return sqlGet(sql, [device_id]) || null;
  }
}

/**
 * Create a new KYC application (or reset an existing non-approved one).
 */
async function createKYCApplication({ device_id, first_name, last_name, dob, id_type }) {
  if (USE_TURSO) {
    await turso.execute({
      sql: `INSERT INTO kyc_applications (device_id, first_name, last_name, dob, id_type, status)
            VALUES (?, ?, ?, ?, ?, 'SESSION_PENDING')`,
      args: [device_id, first_name, last_name, dob, id_type || 'ID_CARD'],
    });
    const rs = await turso.execute({
      sql: 'SELECT * FROM kyc_applications WHERE device_id = ? ORDER BY id DESC LIMIT 1',
      args: [device_id],
    });
    return tursoFirst(rs);
  } else {
    sqlRun(
      `INSERT INTO kyc_applications (device_id, first_name, last_name, dob, id_type, status)
       VALUES (?, ?, ?, ?, ?, 'SESSION_PENDING')`,
      [device_id, first_name, last_name, dob, id_type || 'ID_CARD'],
    );
    return sqlGet('SELECT * FROM kyc_applications WHERE device_id = ? ORDER BY id DESC LIMIT 1', [device_id]);
  }
}

/**
 * Attach a Veriff session ID to a KYC application row.
 */
async function attachVeriffSession(kyc_id, veriff_session_id) {
  if (USE_TURSO) {
    await turso.execute({
      sql:  `UPDATE kyc_applications SET veriff_session_id=?, status='SESSION_CREATED', updated_at=datetime('now') WHERE id=?`,
      args: [veriff_session_id, kyc_id],
    });
  } else {
    sqlRun(
      `UPDATE kyc_applications SET veriff_session_id=?, status='SESSION_CREATED', updated_at=datetime('now') WHERE id=?`,
      [veriff_session_id, kyc_id],
    );
  }
}

/**
 * Update KYC status from a Veriff webhook event.
 * veriffCode: 9001=approved, 9102=declined-resubmit, 9103=declined-final, 9104=expired
 */
async function updateKYCFromWebhook({ veriff_session_id, status, veriff_code, veriff_decision, veriff_person, decline_reason }) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  if (USE_TURSO) {
    await turso.execute({
      sql: `UPDATE kyc_applications SET
              status=?, veriff_code=?, veriff_decision=?, veriff_person=?,
              decline_reason=?, decision_at=?, updated_at=datetime('now')
            WHERE veriff_session_id=?`,
      args: [status, veriff_code || null, veriff_decision || null,
             veriff_person ? JSON.stringify(veriff_person) : null,
             decline_reason || null, now, veriff_session_id],
    });
  } else {
    sqlRun(
      `UPDATE kyc_applications SET
         status=?, veriff_code=?, veriff_decision=?, veriff_person=?,
         decline_reason=?, decision_at=?, updated_at=datetime('now')
       WHERE veriff_session_id=?`,
      [status, veriff_code || null, veriff_decision || null,
       veriff_person ? JSON.stringify(veriff_person) : null,
       decline_reason || null, now, veriff_session_id],
    );
  }
}

/**
 * Update address proof fields for a KYC application.
 */
async function updateKYCAddress({ device_id, address_line1, address_city, address_postcode }) {
  if (USE_TURSO) {
    await turso.execute({
      sql: `UPDATE kyc_applications SET
              address_line1=?, address_city=?, address_postcode=?,
              address_status='SUBMITTED', updated_at=datetime('now')
            WHERE device_id=? AND status IN ('APPROVED','SESSION_CREATED','SESSION_PENDING','PENDING')
            ORDER BY id DESC LIMIT 1`,
      args: [address_line1, address_city, address_postcode, device_id],
    });
  } else {
    const app = sqlGet(
      `SELECT id FROM kyc_applications WHERE device_id=? ORDER BY id DESC LIMIT 1`,
      [device_id],
    );
    if (app) {
      sqlRun(
        `UPDATE kyc_applications SET
           address_line1=?, address_city=?, address_postcode=?,
           address_status='SUBMITTED', updated_at=datetime('now')
         WHERE id=?`,
        [address_line1, address_city, address_postcode, app.id],
      );
    }
  }
}

/**
 * Admin: get all KYC applications for review dashboard.
 */
async function getAllKYCApplications(limit = 100) {
  const sql = `
    SELECT k.*, d.browser, d.os, d.last_ip, d.last_city
    FROM kyc_applications k
    LEFT JOIN devices d ON d.device_id = k.device_id
    ORDER BY k.updated_at DESC
    LIMIT ?
  `;
  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args: [limit] });
    return tursoRows(rs);
  } else {
    return sqlAll(sql, [limit]);
  }
}

// ─── kyc_manual ───────────────────────────────────────────────────────────────

async function submitKYCManual({ device_id, first_name, last_name, dob, adt, afm, amka, id_front, id_back, selfie, validations }) {
  const vals = JSON.stringify(validations || {});
  if (USE_TURSO) {
    await turso.execute({
      sql: `INSERT INTO kyc_manual
              (device_id,first_name,last_name,dob,adt,afm,amka,id_front,id_back,selfie,validations,status)
            VALUES (?,?,?,?,?,?,?,?,?,?,'PENDING')
            ON CONFLICT DO NOTHING`,
      // upsert by device_id — if there's already a PENDING, replace it
      args: [device_id,first_name,last_name,dob,adt||null,afm||null,amka||null,
             id_front||null,id_back||null,selfie||null,vals],
    });
    // If device already has a non-approved application, update it instead
    const existing = await turso.execute({
      sql: `SELECT id,status FROM kyc_manual WHERE device_id=? ORDER BY id DESC LIMIT 1`,
      args: [device_id],
    });
    const row = tursoFirst(existing);
    if (row && row.status !== 'APPROVED') {
      await turso.execute({
        sql: `UPDATE kyc_manual SET
                first_name=?,last_name=?,dob=?,adt=?,afm=?,amka=?,
                id_front=?,id_back=?,selfie=?,validations=?,
                status='PENDING',operator_notes=NULL,reviewed_at=NULL,
                updated_at=datetime('now')
              WHERE id=?`,
        args: [first_name,last_name,dob,adt||null,afm||null,amka||null,
               id_front||null,id_back||null,selfie||null,vals,row.id],
      });
      return row.id;
    }
    // fresh insert
    const ins = await turso.execute({
      sql: `INSERT INTO kyc_manual
              (device_id,first_name,last_name,dob,adt,afm,amka,id_front,id_back,selfie,validations)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      args: [device_id,first_name,last_name,dob,adt||null,afm||null,amka||null,
             id_front||null,id_back||null,selfie||null,vals],
    });
    return Number(ins.lastInsertRowid);
  } else {
    const existing = sqlGet(`SELECT id,status FROM kyc_manual WHERE device_id=? ORDER BY id DESC LIMIT 1`,[device_id]);
    if (existing && existing.status !== 'APPROVED') {
      sqlRun(`UPDATE kyc_manual SET
                first_name=?,last_name=?,dob=?,adt=?,afm=?,amka=?,
                id_front=?,id_back=?,selfie=?,validations=?,
                status='PENDING',operator_notes=NULL,reviewed_at=NULL,
                updated_at=datetime('now')
              WHERE id=?`,
        [first_name,last_name,dob,adt||null,afm||null,amka||null,
         id_front||null,id_back||null,selfie||null,vals,existing.id]);
      return existing.id;
    }
    sqlRun(`INSERT INTO kyc_manual
              (device_id,first_name,last_name,dob,adt,afm,amka,id_front,id_back,selfie,validations)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [device_id,first_name,last_name,dob,adt||null,afm||null,amka||null,
       id_front||null,id_back||null,selfie||null,vals]);
    return sqlGet('SELECT last_insert_rowid() AS id').id;
  }
}

async function getKYCManual(device_id) {
  const sql = `SELECT id,device_id,first_name,last_name,dob,adt,afm,amka,
                      validations,status,operator_notes,reviewed_at,created_at,updated_at
               FROM kyc_manual WHERE device_id=? ORDER BY id DESC LIMIT 1`;
  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args: [device_id] });
    return tursoFirst(rs) || null;
  } else {
    return sqlGet(sql, [device_id]) || null;
  }
}

async function getAllKYCManual(statusFilter = null, limit = 200) {
  const where = statusFilter ? `WHERE km.status=?` : '';
  const sql = `
    SELECT km.id, km.device_id, km.first_name, km.last_name, km.dob,
           km.adt, km.afm, km.amka,
           km.id_front, km.id_back, km.selfie,
           km.validations, km.status, km.operator_notes,
           km.reviewed_at, km.created_at, km.updated_at,
           d.browser, d.os, d.last_ip, d.last_city, d.last_isp
    FROM kyc_manual km
    LEFT JOIN devices d ON d.device_id = km.device_id
    ${where}
    ORDER BY km.updated_at DESC
    LIMIT ?
  `;
  const args = statusFilter ? [statusFilter, limit] : [limit];
  if (USE_TURSO) {
    const rs = await turso.execute({ sql, args });
    return tursoRows(rs);
  } else {
    return sqlAll(sql, args);
  }
}

async function reviewKYCManual(id, { status, operator_notes }) {
  const now = new Date().toISOString().replace('T',' ').slice(0,19);
  if (USE_TURSO) {
    await turso.execute({
      sql: `UPDATE kyc_manual SET status=?,operator_notes=?,reviewed_at=?,updated_at=datetime('now') WHERE id=?`,
      args: [status, operator_notes||null, now, id],
    });
  } else {
    sqlRun(`UPDATE kyc_manual SET status=?,operator_notes=?,reviewed_at=?,updated_at=datetime('now') WHERE id=?`,
      [status, operator_notes||null, now, id]);
  }
}

/** Check if the same ΑΔΤ or ΑΦΜ already exists on a DIFFERENT device (duplicate = fraud) */
async function checkKYCDuplicates(device_id, adt, afm) {
  const result = { adt: [], afm: [] };

  if (adt) {
    const sql = `SELECT device_id,first_name,last_name,status,created_at FROM kyc_manual
                 WHERE adt=? AND device_id != ? AND status != 'REJECTED' LIMIT 10`;
    if (USE_TURSO) {
      const rs = await turso.execute({ sql, args: [adt, device_id] });
      result.adt = tursoRows(rs);
    } else {
      result.adt = sqlAll(sql, [adt, device_id]);
    }
  }

  if (afm) {
    const sql = `SELECT device_id,first_name,last_name,status,created_at FROM kyc_manual
                 WHERE afm=? AND device_id != ? AND status != 'REJECTED' LIMIT 10`;
    if (USE_TURSO) {
      const rs = await turso.execute({ sql, args: [afm, device_id] });
      result.afm = tursoRows(rs);
    } else {
      result.afm = sqlAll(sql, [afm, device_id]);
    }
  }

  return result;
}

async function updateNetworkLabel(network_id, label) {
  if (USE_TURSO) {
    await turso.execute({
      sql:  'UPDATE networks SET label = ? WHERE network_id = ?',
      args: [label, network_id],
    });
  } else {
    sqlRun('UPDATE networks SET label = ? WHERE network_id = ?', [label, network_id]);
  }
}

// ─── Device naming ────────────────────────────────────────────────────────────

async function setDeviceName(device_id, name) {
  const clean = (name || '').trim().slice(0, 64);
  if (!clean) return;
  if (USE_TURSO) {
    await turso.execute({
      sql:  `UPDATE devices SET device_name = ? WHERE device_id = ?`,
      args: [clean, device_id],
    });
  } else {
    sqlRun(`UPDATE devices SET device_name = ? WHERE device_id = ?`, [clean, device_id]);
  }
}

async function getDeviceName(device_id) {
  if (USE_TURSO) {
    const rs = await turso.execute({
      sql:  `SELECT device_name FROM devices WHERE device_id = ? LIMIT 1`,
      args: [device_id],
    });
    const row = tursoFirst(rs);
    return row ? row.device_name : null;
  } else {
    const row = sqlGet(`SELECT device_name FROM devices WHERE device_id = ? LIMIT 1`, [device_id]);
    return row ? row.device_name : null;
  }
}

// ─── IP history ───────────────────────────────────────────────────────────────

async function getIPHistory(ip) {
  // Returns { visitCount, firstSeen, lastSeen, uniqueDevices } for this exact IP
  if (USE_TURSO) {
    const rs = await turso.execute({
      sql:  `SELECT visit_count, first_seen, last_seen FROM networks WHERE ip = ? LIMIT 1`,
      args: [ip],
    });
    const net = tursoFirst(rs);

    // Count unique devices that used this IP via visits
    const drs = await turso.execute({
      sql:  `SELECT COUNT(DISTINCT device_id) AS cnt FROM visits v
             JOIN networks n ON n.network_id = v.network_id
             WHERE n.ip = ?`,
      args: [ip],
    });
    const drow = tursoFirst(drs);

    if (!net) return { isNew: true, visitCount: 0, uniqueDevices: 0, firstSeen: null, lastSeen: null };
    return {
      isNew:         false,
      visitCount:    net.visit_count    || 0,
      uniqueDevices: drow ? (drow.cnt || 0) : 0,
      firstSeen:     net.first_seen     || null,
      lastSeen:      net.last_seen      || null,
    };
  } else {
    const net = sqlGet(`SELECT visit_count, first_seen, last_seen FROM networks WHERE ip = ? LIMIT 1`, [ip]);
    const drow = sqlGet(`SELECT COUNT(DISTINCT v.device_id) AS cnt FROM visits v
                         JOIN networks n ON n.network_id = v.network_id WHERE n.ip = ?`, [ip]);
    if (!net) return { isNew: true, visitCount: 0, uniqueDevices: 0, firstSeen: null, lastSeen: null };
    return {
      isNew:         false,
      visitCount:    net.visit_count    || 0,
      uniqueDevices: drow ? (drow.cnt || 0) : 0,
      firstSeen:     net.first_seen     || null,
      lastSeen:      net.last_seen      || null,
    };
  }
}

module.exports = {
  initDB,
  upsertNetwork,
  upsertDevice,
  insertVisit,
  deviceExists,
  networkExists,
  fingerprintExists,
  getSimilarDevices,
  getRecentNetworksForFingerprint,
  getRecentVisits,
  getDeviceSummaries,
  getNetworkSummaries,
  getStats,
  updateNetworkLabel,
  upsertPaymentMethod,
  getGraphLinks,
  // device naming + IP history + LAN correlation
  setDeviceName,
  getDeviceName,
  getIPHistory,
  getLanCorrelations,
  // ── kyc_manual helpers ──────────────────────────────────────────────────────
  getBINCache,
  setBINCache,
  getDeviceCluster,
  getKYCApplication,
  createKYCApplication,
  attachVeriffSession,
  updateKYCFromWebhook,
  updateKYCAddress,
  getAllKYCApplications,
  // kyc_manual
  submitKYCManual,
  getKYCManual,
  getAllKYCManual,
  reviewKYCManual,
  checkKYCDuplicates,
  clearAllData,
};

// ─── Clear all data ───────────────────────────────────────────────────────────
async function clearAllData() {
  const tables = ['visits', 'devices', 'networks', 'payment_methods', 'bin_cache', 'kyc_manual', 'kyc_applications'];
  if (USE_TURSO) {
    for (const t of tables) {
      await turso.execute(`DELETE FROM ${t}`);
    }
  } else {
    for (const t of tables) {
      sqlRun(`DELETE FROM ${t}`);
    }
  }
  // Reset in-memory caches
  deviceCache.clear();
  networkCache.clear();
  fpCache.clear();
}
