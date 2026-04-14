/**
 * lib/correlation.js
 *
 * 3-tier visit classification:
 *
 *   GREEN  — clean visit (genuine new user, or recognised returning visitor)
 *   ORANGE — suspicious signals (possible identity shift; reason cards explain why)
 *   RED    — high confidence same person trying to appear new
 *
 * The risk engine (similarity.js) scores 0–100.
 * Thresholds:
 *   0        → GREEN
 *   1 – 64   → ORANGE
 *   65+      → RED  (also triggered by a standalone fingerprint-match signal)
 */

'use strict';

const {
  deviceExists,
  networkExists,
  fingerprintExists,
} = require('../database');

const { assessRisk } = require('./similarity');

// Risk score thresholds
const RED_THRESHOLD    = 65;   // high-confidence same person
const ORANGE_THRESHOLD = 1;    // any signal at all

/**
 * Classify a visit.
 * Returns { correlation, label, description, knownDevice, knownNetwork,
 *           fingerprintMatch, riskScore, riskFactors, riskReasons }
 */
function classify({
  device_id,
  network_id,
  fingerprint_id,
  currentDevice,
  currentNetwork,
  getSimilarDevices,
  getRecentNetworksForFingerprint,
}) {
  const knownDevice      = deviceExists(device_id);
  const knownNetwork     = networkExists(network_id);
  const fingerprintMatch = fingerprint_id ? fingerprintExists(fingerprint_id) : false;

  // ── Risk engine ───────────────────────────────────────────────────────────
  const risk = assessRisk({
    currentDevice,
    currentNetwork,
    fingerprint_id,
    knownDevice,
    fingerprintMatch,
    getSimilarDevices,
    getRecentNetworksForFingerprint,
  });

  const { riskScore, riskFactors, riskReasons } = risk;

  // ── 3-tier classification ─────────────────────────────────────────────────
  let correlation, label, description;

  if (riskScore >= RED_THRESHOLD) {
    // RED — very high confidence this is the same person
    correlation = 'RED';
    label       = '⛔ Identity Confirmed';
    description = 'We are highly confident this is a returning visitor attempting to appear as a new user. ' +
                  'Multiple strong signals match a previously seen identity.';

  } else if (riskScore >= ORANGE_THRESHOLD) {
    // ORANGE — suspicious, reason cards explain
    const n = riskFactors.length;
    correlation = 'ORANGE';
    label       = '⚠️ Suspicious Activity';
    description = `${n} risk signal${n !== 1 ? 's' : ''} detected — this visit may not be from a genuine new user. ` +
                  'See the risk analysis below for details.';

  } else {
    // GREEN — clean visit
    correlation = 'GREEN';
    if (knownDevice) {
      label       = '✅ Returning Visitor';
      description = 'This device has visited before. No suspicious signals detected — ' +
                    'this looks like a normal returning user.';
    } else {
      label       = '✅ New Visitor';
      description = 'First time seeing this device and network. No fraud signals detected — ' +
                    'this appears to be a genuine new user.';
    }
  }

  return {
    correlation,
    knownDevice,
    knownNetwork,
    fingerprintMatch,
    riskScore,
    riskFactors,
    riskReasons,
    label,
    description,
  };
}

const COLORS = {
  GREEN:  { hex: '#22c55e', bg: '#dcfce7', border: '#86efac', text: '#14532d' },
  ORANGE: { hex: '#f97316', bg: '#ffedd5', border: '#fdba74', text: '#7c2d12' },
  RED:    { hex: '#ef4444', bg: '#fee2e2', border: '#fca5a5', text: '#7f1d1d' },
  // Legacy — kept for graceful rendering of old DB records
  YELLOW: { hex: '#eab308', bg: '#fef9c3', border: '#fde047', text: '#713f12' },
  BLUE:   { hex: '#3b82f6', bg: '#dbeafe', border: '#93c5fd', text: '#1e3a8a' },
};

module.exports = { classify, COLORS };
