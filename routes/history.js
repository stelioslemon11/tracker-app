/**
 * routes/history.js
 *
 * GET /api/history          — last N visits (default 50)
 * GET /api/devices          — all known devices with summary stats
 * GET /api/networks         — all known networks with summary stats
 * GET /api/stats            — aggregate counts
 */

const express = require('express');
const router  = express.Router();

const {
  getRecentVisits,
  getDeviceSummaries,
  getNetworkSummaries,
  getStats,
} = require('../database');

const { COLORS } = require('../lib/correlation');

// ─── GET /api/history ─────────────────────────────────────────────────────────
router.get('/history', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const visits = getRecentVisits(limit);

  // Attach color metadata so the frontend doesn't have to know the mapping
  const enriched = visits.map(v => ({
    ...v,
    color: COLORS[v.correlation] || COLORS.RED,
  }));

  res.json(enriched);
});

// ─── GET /api/devices ─────────────────────────────────────────────────────────
router.get('/devices', (req, res) => {
  res.json(getDeviceSummaries());
});

// ─── GET /api/networks ────────────────────────────────────────────────────────
router.get('/networks', (req, res) => {
  res.json(getNetworkSummaries());
});

// ─── GET /api/stats ───────────────────────────────────────────────────────────
router.get('/stats', (req, res) => {
  const stats = getStats();
  res.json({ ...stats, colors: COLORS });
});

module.exports = router;
