/**
 * database.js
 *
 * SQLite via sql.js (pure WebAssembly — no native compilation needed).
 * The database is persisted to tracker.db on every write.
 *
 * Usage pattern: call `await initDB()` once at server start, then use the
 * synchronous helper functions exported below.  All write helpers call
 * `persistDB()` internally.
 */

'use strict';

const initSqlJs = require('sql.js');
const fs        = require('fs');
const path      = require('path');

const DB_PATH = path.join(__dirname, 'tracker.db');

let db; // sql.js Database instance

// ─── Schema DDL ──────────────────────────────────────────────────────────────
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS networks (
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
  );

  CREATE TABLE IF NOT EXISTS devices (
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
    first_seen        TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen         TEXT NOT NULL DEFAULT (datetime('now')),
    visit_count       INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS visits (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_time     TEXT NOT NULL DEFAULT (datetime('now')),
    device_id      TEXT NOT NULL,
    network_id     TEXT NOT NULL,
    fingerprint_id TEXT,
    correlation    TEXT NOT NULL,
    raw_data       TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_visits_device  ON visits(device_id);
  CREATE INDEX IF NOT EXISTS idx_visits_network ON visits(network_id);
  CREATE INDEX IF NOT EXISTS idx_visits_time    ON visits(visit_time);
  CREATE INDEX IF NOT EXISTS idx_devices_fp     ON devices(fingerprint_id);
`;

// ─── Init & persist ───────────────────────────────────────────────────────────

async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(SCHEMA);
  persistDB();
  console.log('[DB] SQLite database initialised →', DB_PATH);
}

function persistDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// ─── Low-level helpers ────────────────────────────────────────────────────────

/** Run a SQL statement with bound params; returns nothing. */
function run(sql, params = []) {
  db.run(sql, params);
  persistDB();
}

/** Return the first matching row as a plain object, or undefined. */
function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return undefined;
}

/** Return all matching rows as an array of plain objects. */
function all(sql, params = []) {
  const results = [];
  const stmt    = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

// ─── Upsert helpers ───────────────────────────────────────────────────────────

function upsertNetwork(data) {
  const existing = get('SELECT id FROM networks WHERE network_id = ?', [data.network_id]);

  if (existing) {
    run(`
      UPDATE networks
      SET last_seen   = datetime('now'),
          visit_count = visit_count + 1,
          ip          = ?
      WHERE network_id = ?
    `, [data.ip, data.network_id]);
  } else {
    run(`
      INSERT INTO networks
        (network_id, ip, isp, country, region, city, visit_count)
      VALUES (?, ?, ?, ?, ?, ?, 1)
    `, [
      data.network_id,
      data.ip,
      data.isp     || null,
      data.country || null,
      data.region  || null,
      data.city    || null,
    ]);
  }
}

function upsertDevice(data) {
  const existing = get('SELECT id FROM devices WHERE device_id = ?', [data.device_id]);

  if (existing) {
    run(`
      UPDATE devices
      SET last_seen         = datetime('now'),
          visit_count       = visit_count + 1,
          fingerprint_id    = COALESCE(?, fingerprint_id),
          user_agent        = ?,
          browser           = ?,
          browser_version   = ?,
          os                = ?,
          os_version        = ?,
          device_type       = ?,
          screen_resolution = ?,
          color_depth       = ?,
          timezone          = ?,
          language          = ?,
          platform          = ?,
          cpu_cores         = ?,
          memory_gb         = ?,
          touch_support     = ?
      WHERE device_id = ?
    `, [
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
      data.device_id,
    ]);
  } else {
    run(`
      INSERT INTO devices
        (device_id, fingerprint_id, user_agent, browser, browser_version,
         os, os_version, device_type, screen_resolution, color_depth,
         timezone, language, platform, cpu_cores, memory_gb, touch_support,
         visit_count)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
    `, [
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
    ]);
  }
}

function insertVisit(data) {
  run(`
    INSERT INTO visits
      (device_id, network_id, fingerprint_id, correlation, raw_data)
    VALUES (?, ?, ?, ?, ?)
  `, [
    data.device_id,
    data.network_id,
    data.fingerprint_id || null,
    data.correlation,
    JSON.stringify(data.raw_data),
  ]);
}

// ─── Existence checks (used by correlation classifier) ───────────────────────

function deviceExists(device_id) {
  return !!get('SELECT 1 FROM devices WHERE device_id = ?', [device_id]);
}

function networkExists(network_id) {
  return !!get('SELECT 1 FROM networks WHERE network_id = ?', [network_id]);
}

function fingerprintExists(fingerprint_id) {
  return !!get('SELECT 1 FROM devices WHERE fingerprint_id = ?', [fingerprint_id]);
}

// ─── History / summary queries ────────────────────────────────────────────────

function getRecentVisits(limit = 50) {
  return all(`
    SELECT
      v.id,
      v.visit_time,
      v.correlation,
      v.device_id,
      v.network_id,
      d.browser, d.browser_version, d.os, d.os_version,
      d.device_type, d.screen_resolution, d.timezone,
      d.visit_count AS device_visits,
      n.ip, n.isp, n.city, n.country,
      n.visit_count AS network_visits,
      n.label AS network_label
    FROM visits v
    LEFT JOIN devices  d ON d.device_id  = v.device_id
    LEFT JOIN networks n ON n.network_id = v.network_id
    ORDER BY v.visit_time DESC
    LIMIT ?
  `, [limit]);
}

function getDeviceSummaries() {
  return all(`
    SELECT
      d.*,
      COUNT(v.id)        AS total_visits,
      MAX(v.visit_time)  AS last_visit
    FROM devices d
    LEFT JOIN visits v ON v.device_id = d.device_id
    GROUP BY d.device_id
    ORDER BY d.last_seen DESC
  `);
}

function getNetworkSummaries() {
  return all(`
    SELECT
      n.*,
      COUNT(v.id)              AS total_visits,
      COUNT(DISTINCT v.device_id) AS unique_devices,
      MAX(v.visit_time)        AS last_visit
    FROM networks n
    LEFT JOIN visits v ON v.network_id = n.network_id
    GROUP BY n.network_id
    ORDER BY n.last_seen DESC
  `);
}

function getStats() {
  return get(`
    SELECT
      (SELECT COUNT(*) FROM visits)                           AS total_visits,
      (SELECT COUNT(*) FROM devices)                          AS total_devices,
      (SELECT COUNT(*) FROM networks)                         AS total_networks,
      (SELECT COUNT(*) FROM visits WHERE correlation='GREEN')  AS green_count,
      (SELECT COUNT(*) FROM visits WHERE correlation='YELLOW') AS yellow_count,
      (SELECT COUNT(*) FROM visits WHERE correlation='BLUE')   AS blue_count,
      (SELECT COUNT(*) FROM visits WHERE correlation='RED')    AS red_count
  `);
}

function updateNetworkLabel(network_id, label) {
  run('UPDATE networks SET label = ? WHERE network_id = ?', [label, network_id]);
}

module.exports = {
  initDB,
  upsertNetwork,
  upsertDevice,
  insertVisit,
  deviceExists,
  networkExists,
  fingerprintExists,
  getRecentVisits,
  getDeviceSummaries,
  getNetworkSummaries,
  getStats,
  updateNetworkLabel,
};
