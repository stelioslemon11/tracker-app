/**
 * routes/kyc.js
 *
 * KYC (Know Your Customer) routes — Greek market, powered by Veriff.
 *
 * POST /api/kyc/start            — collect name/DOB, create Veriff session
 * POST /api/kyc/webhook          — receive Veriff decision events (raw body for HMAC)
 * POST /api/kyc/address          — submit address proof (manual review)
 * GET  /api/kyc/status/:device_id — current KYC status for a device
 * GET  /api/kyc/admin            — all applications (admin review queue)
 *
 * Environment variables required:
 *   VERIFF_API_KEY   — Veriff publishable/API key
 *   VERIFF_SECRET    — Veriff secret key (for webhook HMAC)
 *   APP_URL          — public base URL (e.g. https://tracker-app-qeoi.onrender.com)
 */

'use strict';

const express = require('express');
const crypto  = require('crypto');
const fetch   = require('node-fetch');
const router  = express.Router();

const {
  getKYCApplication,
  createKYCApplication,
  attachVeriffSession,
  updateKYCFromWebhook,
  updateKYCAddress,
  getAllKYCApplications,
} = require('../database');

const VERIFF_API_KEY = process.env.VERIFF_API_KEY || '';
const VERIFF_SECRET  = process.env.VERIFF_SECRET  || '';
const APP_URL        = (process.env.APP_URL || 'https://tracker-app-qeoi.onrender.com').replace(/\/$/, '');
const VERIFF_BASE    = 'https://stationapi.veriff.com/v1';

// Minimum age for Greek online gambling (ΕΕΕΠ regulation)
const MIN_AGE_YEARS = 21;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isConfigured() {
  return !!(VERIFF_API_KEY && VERIFF_SECRET);
}

/**
 * Validate Greek date of birth and return age in years.
 * Returns null if invalid format or impossible date.
 */
function parseAndValidateDOB(dob) {
  if (!dob) return null;
  const d = new Date(dob);
  if (isNaN(d.getTime())) return null;
  const now  = new Date();
  let age = now.getFullYear() - d.getFullYear();
  const m = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) age--;
  return age;
}

/**
 * Map Veriff status string + code to our internal status.
 * https://developers.veriff.com/#verification-session-status-codes
 */
function mapVeriffStatus(veriffStatus, code) {
  if (veriffStatus === 'approved')                    return 'APPROVED';
  if (veriffStatus === 'declined' && code === 9102)   return 'RESUBMISSION_REQUESTED';
  if (veriffStatus === 'declined')                    return 'DECLINED';
  if (veriffStatus === 'expired')                     return 'EXPIRED';
  if (veriffStatus === 'abandoned')                   return 'ABANDONED';
  if (veriffStatus === 'submitted')                   return 'PENDING';
  if (veriffStatus === 'started')                     return 'SESSION_CREATED';
  return 'PENDING';
}

// ─── POST /api/kyc/start ──────────────────────────────────────────────────────
// Body: { device_id, first_name, last_name, dob, id_type }
// id_type: "ID_CARD" | "PASSPORT"
router.post('/kyc/start', async (req, res) => {
  try {
    const { device_id, first_name, last_name, dob, id_type = 'ID_CARD' } = req.body || {};

    // Validation
    if (!device_id)   return res.status(400).json({ error: 'device_id required' });
    if (!first_name)  return res.status(400).json({ error: 'first_name required' });
    if (!last_name)   return res.status(400).json({ error: 'last_name required' });
    if (!dob)         return res.status(400).json({ error: 'dob required (YYYY-MM-DD)' });

    // Age gate — 21+ for Greek online gambling
    const age = parseAndValidateDOB(dob);
    if (age === null) return res.status(400).json({ error: 'Invalid date of birth' });
    if (age < MIN_AGE_YEARS) {
      return res.status(403).json({
        error: `Minimum age is ${MIN_AGE_YEARS} years. You are ${age} years old.`,
        code:  'UNDERAGE',
      });
    }

    // Check if already approved
    const existing = await getKYCApplication(device_id);
    if (existing?.status === 'APPROVED') {
      return res.json({ status: 'APPROVED', message: 'KYC already completed and approved.' });
    }

    // Create application record
    const app = await createKYCApplication({ device_id, first_name, last_name, dob, id_type });

    // ── Veriff session creation ───────────────────────────────────────────────
    if (!isConfigured()) {
      // Demo mode — no Veriff keys, simulate the flow
      await attachVeriffSession(app.id, `DEMO-${Date.now()}`);
      return res.json({
        ok:          true,
        demo:        true,
        sessionUrl:  null,
        message:     'Demo mode: set VERIFF_API_KEY + VERIFF_SECRET in Render to enable real verification.',
      });
    }

    const veriffPayload = {
      verification: {
        callback:   `${APP_URL}/api/kyc/webhook`,
        person: {
          firstName: first_name.trim(),
          lastName:  last_name.trim(),
          dateOfBirth: dob,
        },
        document: {
          type:    id_type === 'PASSPORT' ? 'PASSPORT' : 'ID_CARD',
          country: 'GR',
        },
        vendorData:  device_id,
        timestamp:   new Date().toISOString(),
      },
    };

    const veriffRes = await fetch(`${VERIFF_BASE}/sessions`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-AUTH-CLIENT': VERIFF_API_KEY,
      },
      body: JSON.stringify(veriffPayload),
    });

    if (!veriffRes.ok) {
      const errText = await veriffRes.text();
      console.error('[kyc] Veriff session creation failed:', veriffRes.status, errText);
      return res.status(502).json({ error: 'Failed to create verification session. Please try again.' });
    }

    const veriffData = await veriffRes.json();
    const { id: sessionId, url: sessionUrl } = veriffData.verification || {};

    if (!sessionId || !sessionUrl) {
      return res.status(502).json({ error: 'Invalid response from verification provider.' });
    }

    await attachVeriffSession(app.id, sessionId);

    res.json({
      ok:         true,
      sessionId,
      sessionUrl,
    });

  } catch (err) {
    console.error('[kyc] start error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── POST /api/kyc/webhook ────────────────────────────────────────────────────
// Receives raw body — HMAC-SHA256 verified against VERIFF_SECRET
// Veriff sends: decision events, started events, submitted events
router.post('/kyc/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const rawBody  = req.body;
    const sigHeader = (req.headers['x-hmac-signature'] || '').toLowerCase();

    // HMAC verification (skip in demo mode)
    if (isConfigured() && VERIFF_SECRET) {
      const expected = crypto
        .createHmac('sha256', VERIFF_SECRET)
        .update(rawBody)
        .digest('hex')
        .toLowerCase();

      if (expected !== sigHeader) {
        console.warn('[kyc] Webhook HMAC mismatch — rejected');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    const payload = JSON.parse(rawBody.toString('utf8'));
    console.log('[kyc] Webhook received:', JSON.stringify(payload).slice(0, 200));

    // ── Decision event ────────────────────────────────────────────────────────
    if (payload.verification) {
      const v = payload.verification;
      const internalStatus = mapVeriffStatus(v.status, v.code);

      let declineReason = null;
      if (internalStatus === 'DECLINED' || internalStatus === 'RESUBMISSION_REQUESTED') {
        declineReason = v.reason || v.comment || 'Verification could not be completed';
      }

      await updateKYCFromWebhook({
        veriff_session_id: v.id,
        status:            internalStatus,
        veriff_code:       v.code  || null,
        veriff_decision:   v.status,
        veriff_person:     v.person || null,
        decline_reason:    declineReason,
      });

      console.log(`[kyc] Session ${v.id} → ${internalStatus} (code ${v.code})`);
    }

    res.json({ status: 'ok' });
  } catch (err) {
    console.error('[kyc] webhook error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── POST /api/kyc/address ────────────────────────────────────────────────────
// Body: { device_id, address_line1, address_city, address_postcode }
router.post('/kyc/address', async (req, res) => {
  try {
    const { device_id, address_line1, address_city, address_postcode } = req.body || {};

    if (!device_id)      return res.status(400).json({ error: 'device_id required' });
    if (!address_line1)  return res.status(400).json({ error: 'address_line1 required' });
    if (!address_city)   return res.status(400).json({ error: 'address_city required' });
    if (!address_postcode) return res.status(400).json({ error: 'address_postcode required' });

    await updateKYCAddress({ device_id, address_line1, address_city, address_postcode });
    res.json({ ok: true, message: 'Address submitted for review.' });
  } catch (err) {
    console.error('[kyc] address error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /api/kyc/status/:device_id ──────────────────────────────────────────
router.get('/kyc/status/:device_id', async (req, res) => {
  try {
    const app = await getKYCApplication(req.params.device_id);
    if (!app) {
      return res.json({ status: 'NOT_STARTED', configured: isConfigured() });
    }

    // Parse veriff_person JSON if present
    let person = null;
    if (app.veriff_person) {
      try { person = JSON.parse(app.veriff_person); } catch (_) {}
    }

    res.json({
      status:          app.status,
      id_type:         app.id_type,
      address_status:  app.address_status,
      decline_reason:  app.decline_reason || null,
      person,
      created_at:      app.created_at,
      updated_at:      app.updated_at,
      decision_at:     app.decision_at,
      configured:      isConfigured(),
    });
  } catch (err) {
    console.error('[kyc] status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /api/kyc/admin ───────────────────────────────────────────────────────
// Returns all applications for a manual review dashboard
router.get('/kyc/admin', async (req, res) => {
  try {
    const apps = await getAllKYCApplications(200);
    res.json(apps);
  } catch (err) {
    console.error('[kyc] admin error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
