/**
 * lib/similarity.js
 *
 * Device + network similarity scoring engine.
 *
 * Purpose: detect the same person even when they change IP, clear cookies,
 * switch devices, or use a VPN — typical "offer abuse" patterns.
 *
 * Scoring is deliberately transparent: each contributing factor has a fixed
 * weight and a human-readable reason string so the UI can explain exactly
 * why a visitor was flagged.
 */

'use strict';

// ─── Device characteristic weights (sum to 100) ──────────────────────────────
const DEVICE_WEIGHTS = {
  screen_resolution: 22,   // Very device-specific
  timezone:          18,   // Strong geo signal
  browser:           14,   // Common but useful
  os:                14,   // Common but useful
  language:          10,   // Regional signal
  cpu_cores:         10,   // Hardware fingerprint
  memory_gb:         8,    // Hardware fingerprint
  platform:          4,    // Usually Win32/MacIntel/Linux
};

/**
 * Compare two device records and return a similarity score 0–100.
 * 100 = identical profile, 0 = nothing in common.
 */
function deviceSimilarityScore(a, b) {
  if (!a || !b) return 0;
  let score = 0;
  for (const [field, weight] of Object.entries(DEVICE_WEIGHTS)) {
    const va = a[field];
    const vb = b[field];
    if (va && vb && String(va).toLowerCase() === String(vb).toLowerCase()) {
      score += weight;
    }
  }
  return score;
}

// ─── Risk factor definitions ──────────────────────────────────────────────────

const RISK_FACTORS = {
  FINGERPRINT_NO_COOKIE: {
    code:    'FINGERPRINT_NO_COOKIE',
    score:   65,
    label:   'Fingerprint match — cookies cleared',
    detail:  'Canvas/WebGL/Audio fingerprint matches a known device, ' +
             'but the persistent ID is new. Cookies were almost certainly cleared ' +
             'to appear as a new user.',
  },
  HIGH_DEVICE_SIMILARITY_SAME_ISP: {
    code:    'HIGH_DEVICE_SIMILARITY_SAME_ISP',
    score:   55,
    label:   'Very similar device on the same ISP',
    detail:  'A device with nearly identical hardware & software profile ' +
             '(screen, timezone, OS, CPU, RAM) has connected from the same ISP ' +
             'and city. Very likely the same physical machine.',
  },
  HIGH_DEVICE_SIMILARITY_SAME_CITY: {
    code:    'HIGH_DEVICE_SIMILARITY_SAME_CITY',
    score:   45,
    label:   'Similar device — same city',
    detail:  'A closely matching device profile was seen from the same city. ' +
             'Could be the same person on a different connection.',
  },
  SAME_IP_PREFIX_NEW_DEVICE: {
    code:    'SAME_IP_PREFIX_NEW_DEVICE',
    score:   30,
    label:   'Same IP subnet — new device ID',
    detail:  'The first three octets of the IP match a known visitor. ' +
             'The device ID changed (cookie cleared or new browser profile).',
  },
  RAPID_MULTI_NETWORK: {
    code:    'RAPID_MULTI_NETWORK',
    score:   40,
    label:   'Same device — multiple networks in short window',
    detail:  'The same device fingerprint appeared from different networks ' +
             'within a short time. Consistent with VPN switching to appear new.',
  },
  MODERATE_DEVICE_SIMILARITY: {
    code:    'MODERATE_DEVICE_SIMILARITY',
    score:   20,
    label:   'Moderately similar device profile',
    detail:  'Device characteristics overlap with a known visitor profile ' +
             '(same timezone, screen, OS). Worth noting but not conclusive.',
  },
};

/**
 * Run the full risk assessment for an incoming visit.
 *
 * @param {object} params
 *   .currentDevice   — device record of this visit
 *   .currentNetwork  — network record of this visit (with .ip, .isp, .city)
 *   .fingerprint_id  — probabilistic fingerprint hash
 *   .knownDevice     — boolean: device_id already in DB
 *   .fingerprintMatch — boolean: fingerprint_id already in DB with a different device_id
 *   .getSimilarDevices — fn(city, isp) → array of known device records
 *   .getRecentNetworksForFingerprint — fn(fp_id, hoursBack) → array of network records
 *
 * @returns {{ riskScore: number, riskFactors: string[], riskReasons: string[], correlationOverride: string|null }}
 */
function assessRisk({
  currentDevice,
  currentNetwork,
  fingerprint_id,
  knownDevice,
  fingerprintMatch,
  getSimilarDevices,
  getRecentNetworksForFingerprint,
}) {
  const factors   = [];
  let   riskScore = 0;

  const addFactor = (key) => {
    const f = RISK_FACTORS[key];
    if (!f) return;
    factors.push(f);
    riskScore = Math.min(100, riskScore + f.score);
  };

  // 1. Fingerprint match but different device_id (cleared cookies)
  if (fingerprintMatch && !knownDevice) {
    addFactor('FINGERPRINT_NO_COOKIE');
  }

  // 2. Same device seen on multiple networks recently (VPN switching)
  if (fingerprint_id && getRecentNetworksForFingerprint) {
    const recentNets = getRecentNetworksForFingerprint(fingerprint_id, 4); // 4-hour window
    const uniqueNets = new Set(recentNets.map(n => n.network_id));
    if (uniqueNets.size >= 2) {
      addFactor('RAPID_MULTI_NETWORK');
    }
  }

  // 3. Device similarity check against known devices from same ISP / city
  if (currentDevice && getSimilarDevices) {
    const candidates = getSimilarDevices(currentNetwork?.city, currentNetwork?.isp);

    for (const candidate of candidates) {
      // Skip if it's actually the same device_id
      if (candidate.device_id === currentDevice.device_id) continue;

      const simScore = deviceSimilarityScore(currentDevice, candidate);

      if (simScore >= 75) {
        // Strong match — very likely same device
        if (candidate.isp === currentNetwork?.isp) {
          addFactor('HIGH_DEVICE_SIMILARITY_SAME_ISP');
        } else {
          addFactor('HIGH_DEVICE_SIMILARITY_SAME_CITY');
        }
        break; // Don't double-count
      } else if (simScore >= 55) {
        addFactor('MODERATE_DEVICE_SIMILARITY');
        break;
      }
    }
  }

  // 4. Same /24 IP prefix, new device_id
  if (!knownDevice && currentNetwork?.ip) {
    const prefix = currentNetwork.ip.split('.').slice(0, 3).join('.');
    if (getSimilarDevices) {
      const sameSubnet = getSimilarDevices(currentNetwork.city, currentNetwork.isp)
        .filter(d => d.last_ip && d.last_ip.startsWith(prefix));
      if (sameSubnet.length > 0) {
        addFactor('SAME_IP_PREFIX_NEW_DEVICE');
      }
    }
  }

  // Determine if correlation should be overridden to ORANGE
  const correlationOverride = riskScore >= 35 ? 'ORANGE' : null;

  return {
    riskScore:   Math.min(100, riskScore),
    riskFactors: factors.map(f => f.code),
    riskReasons: factors.map(f => ({ label: f.label, detail: f.detail, score: f.score })),
    correlationOverride,
  };
}

module.exports = { deviceSimilarityScore, assessRisk, RISK_FACTORS };
