/**
 * lib/correlation.js
 *
 * Classifies each visit into one of four relationship tiers:
 *
 *   GREEN  — same device  AND same network   (returning visitor, same location)
 *   YELLOW — same network, new device        (different device on the same WiFi/ISP)
 *   BLUE   — same device,  new network       (same device, different location/VPN)
 *   RED    — new device   AND new network    (completely unknown visitor)
 *
 * A secondary "fingerprint match" flag is set when the probabilistic
 * fingerprint_id matches even though the cookie-based device_id is absent
 * (i.e., cookies were cleared).
 */

const {
  deviceExists,
  networkExists,
  fingerprintExists,
} = require('../database');

/**
 * @param {object} params
 * @param {string} params.device_id       — persistent UUID from cookie/localStorage
 * @param {string} params.network_id      — hash derived from IP + ISP prefix
 * @param {string} [params.fingerprint_id] — probabilistic canvas/WebGL/audio hash
 *
 * @returns {{
 *   correlation: 'GREEN'|'YELLOW'|'BLUE'|'RED',
 *   knownDevice:      boolean,
 *   knownNetwork:     boolean,
 *   fingerprintMatch: boolean,
 *   label:            string,
 *   description:      string
 * }}
 */
function classify({ device_id, network_id, fingerprint_id }) {
  const knownDevice      = deviceExists(device_id);
  const knownNetwork     = networkExists(network_id);
  const fingerprintMatch = fingerprint_id
    ? fingerprintExists(fingerprint_id)
    : false;

  let correlation, label, description;

  if (knownDevice && knownNetwork) {
    correlation = 'GREEN';
    label       = 'Same Device & Network';
    description = 'This device has been seen before on this exact network. ' +
                  'This is a clear returning visitor.';

  } else if (!knownDevice && knownNetwork) {
    correlation = 'YELLOW';
    label       = 'Same Network — New Device';
    description = 'This network was seen before with a different device. ' +
                  'Someone on the same WiFi or ISP range has visited previously.';

  } else if (knownDevice && !knownNetwork) {
    correlation = 'BLUE';
    label       = 'Same Device — New Network';
    description = 'This device has been seen before but is now connecting from ' +
                  'a different network (new location, mobile data, or VPN).';

  } else {
    correlation = 'RED';
    label       = 'New Device & New Network';
    description = fingerprintMatch
      ? 'Unknown device and network — but the browser fingerprint matches a ' +
        'previously seen device. Cookies may have been cleared.'
      : 'Completely new device and network. No prior relationship detected.';
  }

  return { correlation, knownDevice, knownNetwork, fingerprintMatch, label, description };
}

/**
 * Human-readable colour name → hex mapping (also used by the frontend).
 */
const COLORS = {
  GREEN:  { hex: '#22c55e', bg: '#dcfce7', border: '#86efac', text: '#14532d' },
  YELLOW: { hex: '#eab308', bg: '#fef9c3', border: '#fde047', text: '#713f12' },
  BLUE:   { hex: '#3b82f6', bg: '#dbeafe', border: '#93c5fd', text: '#1e3a8a' },
  RED:    { hex: '#ef4444', bg: '#fee2e2', border: '#fca5a5', text: '#7f1d1d' },
};

module.exports = { classify, COLORS };
