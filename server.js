/**
 * server.js
 * Express entry point for the Tracker demo app.
 *
 * Usage:
 *   npm install
 *   npm start          # production
 *   npm run dev        # auto-reload via nodemon
 *
 * Endpoints:
 *   POST  /api/visit            — submit a visit payload
 *   PATCH /api/network-label    — label a network
 *   GET   /api/history          — recent visits
 *   GET   /api/devices          — device summaries
 *   GET   /api/networks         — network summaries
 *   GET   /api/stats            — aggregate counts
 */

'use strict';

const express   = require('express');
const path      = require('path');

const { initDB } = require('./database');
const visitRouter   = require('./routes/visit');
const historyRouter = require('./routes/history');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true }));

// Trust the first proxy so req.ip is the real client address when behind
// nginx, Cloudflare, or ngrok.
app.set('trust proxy', 1);

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api', visitRouter);
app.use('/api', historyRouter);

// ─── SPA fallback ─────────────────────────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
(async () => {
  await initDB();               // Wait for sql.js WASM to load + DB to open
  app.listen(PORT, () => {
    console.log(`\n🔍  Tracker app running at http://localhost:${PORT}\n`);
  });
})();

module.exports = app;
