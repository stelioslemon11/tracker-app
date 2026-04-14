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
router.get('/history', async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
  const visits = await getRecentVisits(limit);

  const enriched = visits.map(v => ({
    ...v,
    color: COLORS[v.correlation] || COLORS.RED,
  }));

  res.json(enriched);
});

// ─── GET /api/devices ─────────────────────────────────────────────────────────
router.get('/devices', async (req, res) => {
  res.json(await getDeviceSummaries());
});

// ─── GET /api/networks ────────────────────────────────────────────────────────
router.get('/networks', async (req, res) => {
  res.json(await getNetworkSummaries());
});

// ─── GET /api/stats ───────────────────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  const stats = await getStats();
  res.json({ ...stats, colors: COLORS });
});

module.exports = router;
