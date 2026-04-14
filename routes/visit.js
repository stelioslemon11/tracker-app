/**
 * routes/visit.js
 *
 * POST /api/visit
 *   Receives the browser-collected payload, enriches it with server-side IP
 *   data, runs the correlation classifier, persists everything, and returns
 *   the full result to the client.
 *
 * PATCH /api/network-label
 *   Lets the user assign a human-readable label to a network (e.g. "Home WiFi").
 */

const express = require('express');
const router  = express.Router();

const { lookupIP, buildNetworkId } = require('../lib/ipLookup');
const { parseUA }                  = require('../lib/deviceParser');
const { classify, COLORS }         = require('../lib/correlation');
const {
  upsertNetwork,
  upsertDevice,
  insertVisit,
  getNetworkSummaries,
  updateNetworkLabel,
} = require('../database');

// ─── POST /api/visit ──────────────────────────────────────────────────────────
router.post('/visit', async (req, res) => {
  try {
    // 1. Extract real client IP (works behind proxies / ngrok)
    const ip =
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.socket.remoteAddress ||
      '0.0.0.0';

    // 2. Body from client-side collector
    const {
      device_id,
      fingerprint_id,
      screen_resolution,
      color_depth,
      timezone,
      language,
      platform,
      cpu_cores,
      memory_gb,
      touch_support,
    } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: 'device_id is required' });
    }

    // 3. Enrich with IP lookup
    const geo        = await lookupIP(ip);
    const network_id = buildNetworkId(ip, geo.isp);

    // 4. Parse user-agent
    const ua      = req.headers['user-agent'] || '';
    const parsed  = parseUA(ua);

    // 5. Classify the visit BEFORE we write (so we see "known" state)
    const classResult = classify({ device_id, network_id, fingerprint_id });

    // 6. Upsert network + device records
    upsertNetwork({
      network_id,
      ip,
      isp:     geo.isp,
      country: geo.country,
      region:  geo.region,
      city:    geo.city,
    });

    upsertDevice({
      device_id,
      fingerprint_id,
      user_agent:        ua,
      browser:           parsed.browser,
      browser_version:   parsed.browser_version,
      os:                parsed.os,
      os_version:        parsed.os_version,
      device_type:       parsed.device_type,
      screen_resolution: screen_resolution || null,
      color_depth:       color_depth       || null,
      timezone:          timezone          || null,
      language:          language          || null,
      platform:          platform          || null,
      cpu_cores:         cpu_cores         || null,
      memory_gb:         memory_gb         || null,
      touch_support:     !!touch_support,
    });

    // 7. Record the visit
    const rawData = {
      ip,
      geo,
      ua,
      device_id,
      fingerprint_id,
      screen_resolution,
      color_depth,
      timezone,
      language,
      platform,
      cpu_cores,
      memory_gb,
      touch_support,
      ...parsed,
    };

    insertVisit({
      device_id,
      network_id,
      fingerprint_id,
      correlation: classResult.correlation,
      raw_data:    rawData,
    });

    // 8. Fetch the current network label (if any)
    const networks = getNetworkSummaries();
    const netInfo  = networks.find(n => n.network_id === network_id) || {};

    // 9. Build response
    const color = COLORS[classResult.correlation];

    res.json({
      correlation:      classResult.correlation,
      label:            classResult.label,
      description:      classResult.description,
      knownDevice:      classResult.knownDevice,
      knownNetwork:     classResult.knownNetwork,
      fingerprintMatch: classResult.fingerprintMatch,
      color,
      device: {
        device_id,
        fingerprint_id:    fingerprint_id || null,
        browser:           parsed.browser,
        browser_version:   parsed.browser_version,
        os:                parsed.os,
        os_version:        parsed.os_version,
        device_type:       parsed.device_type,
        screen_resolution: screen_resolution || null,
        timezone:          timezone          || null,
        language:          language          || null,
        platform:          platform          || null,
        cpu_cores:         cpu_cores         || null,
        memory_gb:         memory_gb         || null,
        touch_support:     !!touch_support,
      },
      network: {
        network_id,
        ip,
        isp:           geo.isp,
        city:          geo.city,
        region:        geo.region,
        country:       geo.country,
        lat:           geo.lat,
        lon:           geo.lon,
        label:         netInfo.label         || null,
        visit_count:   netInfo.total_visits   || 1,
        unique_devices: netInfo.unique_devices || 1,
      },
    });

  } catch (err) {
    console.error('[POST /api/visit]', err);
    res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
});

// ─── PATCH /api/network-label ─────────────────────────────────────────────────
router.patch('/network-label', (req, res) => {
  const { network_id, label } = req.body;
  if (!network_id || !label) {
    return res.status(400).json({ error: 'network_id and label are required' });
  }
  updateNetworkLabel(network_id, label.trim().slice(0, 64));
  res.json({ ok: true });
});

module.exports = router;
