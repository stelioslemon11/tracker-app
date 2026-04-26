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
  getIPHistory,
  getDeviceName,
  setDeviceName,
  getLanCorrelations,
} = require('../database');

// ─── POST /api/visit ──────────────────────────────────────────────────────────
router.post('/visit', async (req, res) => {
  // Safety-net: never hang the client longer than 25 seconds
  const _hangGuard = setTimeout(() => {
    if (!res.headersSent) {
      console.error('[POST /api/visit] 25s timeout — sending 504');
      res.status(504).json({ error: 'Request timed out. Server may be starting up, please retry.' });
    }
  }, 25000);

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
      lan_peers,
      local_ip,
    } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: 'device_id is required' });
    }

    // 3. IP geolookup + parse UA
    // Wrap lookupIP in a hard 5s timeout — node-fetch's internal timeout
    // doesn't cancel during DNS resolution, which can hang for 30+ seconds.
    const GEO_FALLBACK = { isp:'Unknown', country:'', countryCode:'', region:'', city:'', lat:0, lon:0, org:'', query:ip };
    const [geo, ua] = await Promise.all([
      Promise.race([
        lookupIP(ip),
        new Promise(resolve => setTimeout(() => resolve(GEO_FALLBACK), 5000)),
      ]),
      Promise.resolve(req.headers['user-agent'] || ''),
    ]);
    const network_id = buildNetworkId(ip, geo.isp);
    const parsed     = parseUA(ua);

    // 4. Pre-fetch similarity data + IP history + device name (all in parallel)
    const [similarDevices, recentNetworks, ipHistory, deviceName] = await Promise.all([
      getSimilarDevices(geo.city, geo.isp, device_id),
      fingerprint_id
        ? getRecentNetworksForFingerprint(fingerprint_id, 4)
        : Promise.resolve([]),
      getIPHistory(ip),
      getDeviceName(device_id),
    ]);

    // Normalise lan_peers (kept for schema compatibility, currently unused)
    let lan_peers_json = null;
    if (lan_peers) {
      lan_peers_json = typeof lan_peers === 'string' ? lan_peers : JSON.stringify(lan_peers);
    }

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
    // local_ip is stored inside raw_data JSON (avoids schema-column issues);
    // getLanCorrelations queries it via json_extract(raw_data, '$.local_ip')
    const rawData = {
      ip, geo, ua, device_id, fingerprint_id,
      screen_resolution, color_depth, timezone, language,
      platform, cpu_cores, memory_gb, touch_support,
      local_ip: local_ip || null,
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
      lan_peers:    lan_peers_json,
      local_ip:     local_ip || null,
    });

    // LAN correlation — find devices on same local subnet + same external network
    const lanMatches = await getLanCorrelations(device_id, network_id, local_ip || null);

    // 9. Fetch current network label (with 8s timeout)
    const networks = await Promise.race([
      getNetworkSummaries(),
      new Promise(resolve => setTimeout(() => resolve([]), 8000)),
    ]);
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
        device_name:       deviceName || null,
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
      ipHistory,
      lanMatches,
      localIP: local_ip || null,
    });
    clearTimeout(_hangGuard);

  } catch (err) {
    clearTimeout(_hangGuard);
    console.error('[POST /api/visit]', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error', detail: err.message });
    }
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

// ─── POST /api/device/name ────────────────────────────────────────────────────
router.post('/device/name', async (req, res) => {
  const { device_id, name } = req.body;
  if (!device_id || !name) {
    return res.status(400).json({ error: 'device_id and name are required' });
  }
  await setDeviceName(device_id, name);
  res.json({ ok: true });
});

// ─── GET /api/device/name/:device_id ─────────────────────────────────────────
router.get('/device/name/:device_id', async (req, res) => {
  const name = await getDeviceName(req.params.device_id);
  res.json({ device_name: name || null });
});

module.exports = router;
