/**
 * lib/correlation.js
 *
 * Visit classification into 5 tiers:
 *
 *   GREEN  — same device  AND same network  (confirmed returning visitor)
 *   YELLOW — same network, new device       (someone else on same WiFi/ISP)
 *   BLUE   — same device,  new network      (same device, moved/VPN)
 *   ORANGE — suspected same person          (high risk score, identity shift)
 *   RED    — completely new visitor         (low/zero risk, genuinely new)
 *
 * Risk scoring (0–100) runs independently and can override RED→ORANGE.
 */

'use strict';

const {
  deviceExists,
  networkExists,
  fingerprintExists,
} = require('../database');

const { assessRisk } = require('./similarity');

/**
 * Classify a visit and run fraud-risk assessment.
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

  // ── Base tier ─────────────────────────────────────────────────────────────
  let baseTier, label, description;

  if (knownDevice && knownNetwork) {
    baseTier    = 'GREEN';
    label       = 'Same Device & Network';
    description = 'This device has been seen before on this exact network — clear returning visitor.';
  } else if (!knownDevice && knownNetwork) {
    baseTier    = 'YELLOW';
    label       = 'Same Network — New Device';
    description = 'This network was seen before with a different device. Someone on the same WiFi or ISP range has visited previously.';
  } else if (knownDevice && !knownNetwork) {
    baseTier    = 'BLUE';
    label       = 'Same Device — New Network';
    description = 'This device has been seen before but is now connecting from a different network (new location, mobile data, or VPN).';
  } else {
    baseTier    = 'RED';
    label       = 'New Device & New Network';
    description = 'No prior relationship detected.';
  }

  // ── Risk assessment ───────────────────────────────────────────────────────
  const risk = assessRisk({
    currentDevice,
    currentNetwork,
    fingerprint_id,
    knownDevice,
    fingerprintMatch,
    getSimilarDevices,
    getRecentNetworksForFingerprint,
  });

  // ── Apply ORANGE override only when base tier is RED or BLUE ─────────────
  let correlation = baseTier;
  if (risk.correlationOverride === 'ORANGE' && (baseTier === 'RED' || baseTier === 'BLUE')) {
    correlation = 'ORANGE';
    label       = 'Suspected Identity Shift';
    description = 'Risk signals suggest this may be a known visitor disguising as a new user. ' +
                  'See risk factors below for details.';
  }

  // Enrich RED description if fingerprint matches
  if (correlation === 'RED' && fingerprintMatch) {
    description = 'Unknown device & network — but the browser fingerprint matches a previously ' +
                  'seen device. Cookies were likely cleared.';
  }

  return {
    correlation,
    knownDevice,
    knownNetwork,
    fingerprintMatch,
    riskScore:   risk.riskScore,
    riskFactors: risk.riskFactors,
    riskReasons: risk.riskReasons,
    label,
    description,
  };
}

const COLORS = {
  GREEN:  { hex: '#22c55e', bg: '#dcfce7', border: '#86efac', text: '#14532d' },
  YELLOW: { hex: '#eab308', bg: '#fef9c3', border: '#fde047', text: '#713f12' },
  BLUE:   { hex: '#3b82f6', bg: '#dbeafe', border: '#93c5fd', text: '#1e3a8a' },
  ORANGE: { hex: '#f97316', bg: '#ffedd5', border: '#fdba74', text: '#7c2d12' },
  RED:    { hex: '#ef4444', bg: '#fee2e2', border: '#fca5a5', text: '#7f1d1d' },
};

module.exports = { classify, COLORS };
