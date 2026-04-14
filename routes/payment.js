/**
 * routes/payment.js
 *
 * POST /api/payment   — hash a card number, store it, return match info
 * GET  /api/graph/:device_id — return all connection types for a device
 */

'use strict';

const express  = require('express');
const crypto   = require('crypto');
const router   = express.Router();

const fetch = require('node-fetch');
const { upsertPaymentMethod, getGraphLinks, getBINCache, setBINCache, getDeviceCluster } = require('../database');

// ─── POST /api/payment ────────────────────────────────────────────────────────
// Body: { device_id, card_number }
// card_number can include spaces — we strip them before hashing
router.post('/payment', async (req, res) => {
  try {
    const { device_id, card_number } = req.body || {};

    if (!device_id) {
      return res.status(400).json({ error: 'device_id required' });
    }
    if (!card_number) {
      return res.status(400).json({ error: 'card_number required' });
    }

    const digits = String(card_number).replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) {
      return res.status(400).json({ error: 'card_number must be 13–19 digits' });
    }

    const token = crypto.createHash('sha256').update(digits).digest('hex');
    const last4 = digits.slice(-4);
    const bin   = digits.slice(0, 6);   // first 6 digits — BIN / IIN
    const bin8  = digits.length >= 8 ? digits.slice(0, 8) : null;  // extended BIN (issuer fingerprint)

    const { isNew, matchingDevices } = await upsertPaymentMethod({ token, last4, bin, bin8, device_id });

    res.json({
      ok: true,
      last4,
      bin,
      bin8,
      isNew,                           // true  = first time this card was seen at all
      alreadyLinked: !isNew,           // true  = this device already registered this card
      matchCount: matchingDevices.length,
      matchingDevices,
    });
  } catch (err) {
    console.error('[payment] error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /api/graph/:device_id ────────────────────────────────────────────────
// Query params: fingerprint_id, ip
router.get('/graph/:device_id', async (req, res) => {
  try {
    const { device_id }    = req.params;
    const { fingerprint_id, ip } = req.query;

    const links = await getGraphLinks({
      device_id,
      fingerprint_id: fingerprint_id || null,
      ip:             ip             || null,
    });

    res.json(links);
  } catch (err) {
    console.error('[graph] error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /api/bin/:bin ────────────────────────────────────────────────────────
// Look up card issuer via binlist.net (free API), cache results in DB
// :bin can be 6–8 digits
router.get('/bin/:bin', async (req, res) => {
  try {
    const raw  = req.params.bin.replace(/\D/g, '');
    const bin6 = raw.slice(0, 6);
    if (bin6.length < 6) return res.status(400).json({ error: 'Need at least 6 digits' });

    // 1. Check cache
    const cached = await getBINCache(bin6);
    if (cached) return res.json({ ...cached, _source: 'cache' });

    // 2. Call binlist.net
    let data = null;
    try {
      const apiRes = await fetch(`https://lookup.binlist.net/${bin6}`, {
        headers: { 'Accept-Version': '3' },
        timeout: 4000,
      });
      if (apiRes.ok) {
        const raw = await apiRes.json();
        data = {
          scheme:   raw.scheme   || null,   // visa / mastercard / amex
          type:     raw.type     || null,   // debit / credit / prepaid
          brand:    raw.brand    || null,
          prepaid:  raw.prepaid  || false,
          bank:     raw.bank?.name    || null,
          bankUrl:  raw.bank?.url     || null,
          bankPhone: raw.bank?.phone  || null,
          country:  raw.country?.name || null,
          countryEmoji: raw.country?.emoji || null,
        };
        await setBINCache(bin6, data);
      }
    } catch (fetchErr) {
      console.warn('[bin] binlist.net lookup failed:', fetchErr.message);
    }

    if (!data) return res.status(404).json({ error: 'BIN not found' });
    res.json({ ...data, _source: 'api' });

  } catch (err) {
    console.error('[bin] error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /api/cluster/:device_id ─────────────────────────────────────────────
// Returns the full connected component (BFS over all link types)
router.get('/cluster/:device_id', async (req, res) => {
  try {
    const { device_id } = req.params;
    const result = await getDeviceCluster(device_id);
    res.json(result);
  } catch (err) {
    console.error('[cluster] error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
