/**
 * routes/visit.js
 *
 * POST /api/visit
 *   Receives the browser-collected payload, enriches it with server-side IP
 *   data, runs the full risk + correlation engine, persists everything, and
 *   returns the result to the client.
 *
 * PATCH /api/network-label
 *   Lets the user assign a human-readable label to a network.
 */

const express = require('express');
const router  = express.Router();

const { lookupIP, buildNetworkId }          = require('../lib/ipLookup');
const { parseUA }                            = require('../lib/deviceParser');
const { classify, COLORS }                   = require('../lib/correlation');
const {
  upsertNetwork,
  upsertDevice,
  insertVisit,
  getNetworkSummaries,
  updateNetworkLabel,
  getSimilarDevices,
  getRecentNetworksForFingerprint,
} = require('../database');

// ─── POST /api/visit ──────────────────────────────────────────────────────────
router.post('/visit', async (req, res) => {
  try {
    // 1. Real client IP (handles proxies / Render / ngrok)
    const ip =
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.socket.remoteAddress ||
      '0.0.0.0';

    // 2. Client-side payload
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

    // 3. IP geolookup + parse UA
    const [geo, ua] = await Promise.all([
      lookupIP(ip),
      Promise.resolve(req.headers['user-agent'] || ''),
    ]);
    const network_id = buildNetworkId(ip, geo.isp);
    const parsed     = parseUA(ua);

    // 4. Pre-fetch similarity data (async, BEFORE classify so DB is pre-write state)
    const [similarDevices, recentNetworks] = await Promise.all([
      getSimilarDevices(geo.city, geo.isp, device_id),
      fingerprint_id
        ? getRecentNetworksForFingerprint(fingerprint_id, 4)
        : Promise.resolve([]),
    ]);

    // 5. Build currentDevice + currentNetwork objects for the risk engine
    const currentDevice = {
      device_id,
      screen_resolution: screen_resolution || null,
      timezone:          timezone          || null,
      browser:           parsed.browser    || null,
      os:                parsed.os         || null,
      language:          language          || null,
      cpu_cores:         cpu_cores         || null,
      memory_gb:         memory_gb         || null,
      platform:          platform          || null,
    };

    const currentNetwork = {
      ip,
      isp:  geo.isp  || null,
      city: geo.city || null,
    };

    // 6. Run correlation + risk classifier (sync — uses pre-fetched data via closures)
    const classResult = classify({
      device_id,
      network_id,
      fingerprint_id,
      currentDevice,
      currentNetwork,
      getSimilarDevices:               () => similarDevices,
      getRecentNetworksForFingerprint: () => recentNetworks,
    });

    // 7. Persist network + device (updates in-memory caches too)
    await upsertNetwork({
      network_id,
      ip,
      isp:     geo.isp,
      country: geo.country,
      region:  geo.region,
      city:    geo.city,
    });

    await upsertDevice({
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
      last_ip:           ip,
      last_isp:          geo.isp  || null,
      last_city:         geo.city || null,
    });

    // 8. Record visit with risk data
    const rawData = {
      ip, geo, ua, device_id, fingerprint_id,
      screen_resolution, color_depth, timezone, language,
      platform, cpu_cores, memory_gb, touch_support,
      ...parsed,
    };

    await insertVisit({
      device_id,
      network_id,
      fingerprint_id,
      correlation:  classResult.correlation,
      risk_score:   classResult.riskScore,
      risk_factors: JSON.stringify(classResult.riskFactors),
      raw_data:     rawData,
    });

    // 9. Fetch current network label
    const networks = await getNetworkSummaries();
    const netInfo  = networks.find(n => n.network_id === network_id) || {};

    // 10. Respond
    const color = COLORS[classResult.correlation];

    res.json({
      correlation:      classResult.correlation,
      label:            classResult.label,
      description:      classResult.description,
      knownDevice:      classResult.knownDevice,
      knownNetwork:     classResult.knownNetwork,
      fingerprintMatch: classResult.fingerprintMatch,
      riskScore:        classResult.riskScore,
      riskReasons:      classResult.riskReasons,   // [{label, detail, score}]
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
        isp:            geo.isp,
        city:           geo.city,
        region:         geo.region,
        country:        geo.country,
        lat:            geo.lat,
        lon:            geo.lon,
        label:          netInfo.label          || null,
        visit_count:    netInfo.total_visits   || 1,
        unique_devices: netInfo.unique_devices || 1,
      },
    });

  } catch (err) {
    console.error('[POST /api/visit]', err);
    res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
});

// ─── PATCH /api/network-label ─────────────────────────────────────────────────
router.patch('/network-label', async (req, res) => {
  const { network_id, label } = req.body;
  if (!network_id || !label) {
    return res.status(400).json({ error: 'network_id and label are required' });
  }
  await updateNetworkLabel(network_id, label.trim().slice(0, 64));
  res.json({ ok: true });
});

module.exports = router;
