/**
 * routes/kyc.js  —  Manual KYC review system (Greek market)
 *
 * POST /api/kyc/submit              user submits details + base64 photos
 * GET  /api/kyc/status/:device_id   user polls their application status
 * GET  /api/kyc/admin               operator review queue  (requires ?pw=ADMIN_PASSWORD)
 * POST /api/kyc/review/:id          operator approves / rejects
 *
 * Greek-specific validations (all server-side, no external API):
 *   • ΑΦΜ  — 9-digit checksum algorithm
 *   • ΑΜΚΑ — first 6 digits encode DDMMYY, must match stated DOB
 *   • ΑΔΤ  — format check: 1–2 letters + 6–7 digits
 *   • Age  — minimum 21 years (ΕΕΕΠ regulation)
 *   • Duplicate ΑΔΤ / ΑΦΜ across different devices → fraud signal
 */

'use strict';

const express = require('express');
const router  = express.Router();

const {
  submitKYCManual,
  getKYCManual,
  getAllKYCManual,
  reviewKYCManual,
  checkKYCDuplicates,
} = require('../database');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const MIN_AGE        = 21;
const MAX_IMG_BYTES  = 3 * 1024 * 1024; // 3 MB per image (base64 ~4MB)

// ─── Greek validation functions ───────────────────────────────────────────────

/**
 * ΑΦΜ checksum algorithm (Greek tax number, 9 digits).
 * Returns { valid: bool, reason: string }
 */
function validateAFM(afm) {
  const s = String(afm || '').replace(/\s/g, '');
  if (!/^\d{9}$/.test(s))       return { valid: false, reason: 'Πρέπει να είναι 9 ψηφία' };
  if (s === '000000000')         return { valid: false, reason: 'Μη έγκυρο ΑΦΜ' };

  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += parseInt(s[i]) * Math.pow(2, 8 - i);
  }
  const check = (sum % 11) % 10;
  if (check !== parseInt(s[8])) return { valid: false, reason: 'Λανθασμένο ψηφίο ελέγχου' };
  return { valid: true, reason: 'Έγκυρο' };
}

/**
 * ΑΜΚΑ validation: 11 digits, first 6 = DDMMYY of birth.
 * Returns { valid: bool, dobMatch: bool|null, reason: string }
 */
function validateAMKA(amka, dob) {
  const s = String(amka || '').replace(/\s/g, '');
  if (!/^\d{11}$/.test(s)) return { valid: false, dobMatch: null, reason: 'Πρέπει να είναι 11 ψηφία' };

  const dd = s.slice(0, 2);
  const mm = s.slice(2, 4);
  const yy = s.slice(4, 6);

  let dobMatch = null;
  if (dob) {
    const parts = dob.split('-'); // YYYY-MM-DD
    if (parts.length === 3) {
      const dobDD = parts[2].padStart(2, '0');
      const dobMM = parts[1].padStart(2, '0');
      const dobYY = parts[0].slice(-2);
      dobMatch = dd === dobDD && mm === dobMM && yy === dobYY;
    }
  }

  return {
    valid:    true,
    dobMatch,
    reason:   dobMatch === false
      ? `Ασυμφωνία ημερομηνίας: ΑΜΚΑ υποδηλώνει ${dd}/${mm}/${yy}`
      : 'Έγκυρο',
  };
}

/**
 * ΑΔΤ format check: 1–2 letters (Greek or Latin) followed by 6–7 digits.
 */
function validateADT(adt) {
  const s = String(adt || '').replace(/\s/g, '').toUpperCase();
  const ok = /^[A-ZΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ]{1,2}\d{6,7}$/.test(s);
  return {
    valid:  ok,
    reason: ok ? 'Έγκυρη μορφή' : 'Αναμένεται: 1–2 γράμματα + 6–7 ψηφία (π.χ. ΑΒ 123456)',
  };
}

/**
 * Age check from DOB string (YYYY-MM-DD). Returns age in years, or null.
 */
function calcAge(dob) {
  if (!dob) return null;
  const d = new Date(dob);
  if (isNaN(d)) return null;
  const now  = new Date();
  let age    = now.getFullYear() - d.getFullYear();
  const m    = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) age--;
  return age;
}

// ─── POST /api/kyc/submit ─────────────────────────────────────────────────────
router.post('/kyc/submit', async (req, res) => {
  try {
    const {
      device_id, first_name, last_name, dob,
      adt, afm, amka,
      id_front, id_back, selfie,   // base64 strings from client
    } = req.body || {};

    // Required fields
    if (!device_id)  return res.status(400).json({ error: 'device_id required' });
    if (!first_name) return res.status(400).json({ error: 'Απαιτείται όνομα' });
    if (!last_name)  return res.status(400).json({ error: 'Απαιτείται επώνυμο' });
    if (!dob)        return res.status(400).json({ error: 'Απαιτείται ημερομηνία γέννησης' });

    // Age gate
    const age = calcAge(dob);
    if (age === null) return res.status(400).json({ error: 'Μη έγκυρη ημερομηνία γέννησης' });
    if (age < MIN_AGE) {
      return res.status(403).json({
        error: `Ελάχιστη ηλικία ${MIN_AGE} ετών (ΕΕΕΠ). Είστε ${age} ετών.`,
        code:  'UNDERAGE',
      });
    }

    // Image size guard
    for (const [name, img] of [['id_front', id_front], ['id_back', id_back], ['selfie', selfie]]) {
      if (img && img.length > MAX_IMG_BYTES * 1.4) { // base64 is ~1.37× binary
        return res.status(413).json({ error: `Η εικόνα ${name} είναι πολύ μεγάλη (max 3MB)` });
      }
    }

    // Run validations
    const afmResult  = afm  ? validateAFM(afm)          : null;
    const amkaResult = amka ? validateAMKA(amka, dob)   : null;
    const adtResult  = adt  ? validateADT(adt)           : null;

    // Cross-account duplicate check
    const dupes = await checkKYCDuplicates(device_id, adt || null, afm || null);

    const validations = {
      age,
      afm:  afmResult,
      amka: amkaResult,
      adt:  adtResult,
      duplicateADT: dupes.adt,
      duplicateAFM: dupes.afm,
      hasIdFront:  !!id_front,
      hasIdBack:   !!id_back,
      hasSelfie:   !!selfie,
    };

    // Insert / update application
    const id = await submitKYCManual({
      device_id,
      first_name: first_name.trim(),
      last_name:  last_name.trim(),
      dob,
      adt:  adt  ? String(adt).replace(/\s/g, '').toUpperCase()  : null,
      afm:  afm  ? String(afm).replace(/\s/g, '')                 : null,
      amka: amka ? String(amka).replace(/\s/g, '')                : null,
      id_front: id_front || null,
      id_back:  id_back  || null,
      selfie:   selfie   || null,
      validations,
    });

    res.json({
      ok: true,
      id,
      validations,
      warnings: [
        ...(afmResult  && !afmResult.valid          ? [`ΑΦΜ: ${afmResult.reason}`]          : []),
        ...(amkaResult && !amkaResult.valid          ? [`ΑΜΚΑ: ${amkaResult.reason}`]         : []),
        ...(amkaResult && amkaResult.dobMatch===false? [`ΑΜΚΑ: ${amkaResult.reason}`]         : []),
        ...(adtResult  && !adtResult.valid           ? [`ΑΔΤ: ${adtResult.reason}`]           : []),
        ...(dupes.adt.length > 0 ? [`ΑΔΤ χρησιμοποιείται σε ${dupes.adt.length} άλλο(α) λογαριασμό(ους)`] : []),
        ...(dupes.afm.length > 0 ? [`ΑΦΜ χρησιμοποιείται σε ${dupes.afm.length} άλλο(α) λογαριασμό(ους)`] : []),
      ],
    });
  } catch (err) {
    console.error('[kyc/submit]', err);
    res.status(500).json({ error: 'Σφάλμα διακομιστή' });
  }
});

// ─── GET /api/kyc/status/:device_id ──────────────────────────────────────────
router.get('/kyc/status/:device_id', async (req, res) => {
  try {
    const app = await getKYCManual(req.params.device_id);
    if (!app) return res.json({ status: 'NOT_STARTED' });

    let validations = null;
    try { validations = app.validations ? JSON.parse(app.validations) : null; } catch (_) {}

    res.json({
      status:         app.status,
      first_name:     app.first_name,
      last_name:      app.last_name,
      operator_notes: app.operator_notes,
      validations,
      created_at:     app.created_at,
      updated_at:     app.updated_at,
      reviewed_at:    app.reviewed_at,
    });
  } catch (err) {
    console.error('[kyc/status]', err);
    res.status(500).json({ error: 'Σφάλμα διακομιστή' });
  }
});

// ─── GET /api/kyc/admin ───────────────────────────────────────────────────────
router.get('/kyc/admin', async (req, res) => {
  if (req.query.pw !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const status = req.query.status || null; // filter: PENDING, APPROVED, REJECTED
    const apps   = await getAllKYCManual(status, 200);
    res.json(apps);
  } catch (err) {
    console.error('[kyc/admin]', err);
    res.status(500).json({ error: 'Σφάλμα διακομιστή' });
  }
});

// ─── POST /api/kyc/review/:id ─────────────────────────────────────────────────
router.post('/kyc/review/:id', async (req, res) => {
  if (req.query.pw !== ADMIN_PASSWORD && req.body?.pw !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const { status, operator_notes } = req.body || {};
    if (!['APPROVED','REJECTED'].includes(status)) {
      return res.status(400).json({ error: 'status must be APPROVED or REJECTED' });
    }
    await reviewKYCManual(Number(req.params.id), { status, operator_notes });
    res.json({ ok: true });
  } catch (err) {
    console.error('[kyc/review]', err);
    res.status(500).json({ error: 'Σφάλμα διακομιστή' });
  }
});

module.exports = router;
