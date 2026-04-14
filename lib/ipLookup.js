/**
 * lib/ipLookup.js
 * Resolves an IP address to ISP / geo data using ip-api.com (free tier).
 * Falls back gracefully when offline or rate-limited.
 */

const fetch = require('node-fetch');

const CACHE = new Map();          // In-memory cache to avoid hammering the API
const CACHE_TTL_MS = 10 * 60 * 1000;  // 10 minutes

/**
 * Look up geo + ISP info for a given IP.
 * @param {string} ip
 * @returns {Promise<{isp, country, countryCode, region, city, lat, lon, org, query}>}
 */
async function lookupIP(ip) {
  // Skip lookup for loopback / private addresses
  if (isPrivateOrLoopback(ip)) {
    return {
      isp: 'Local Network',
      country: 'Local',
      countryCode: 'LO',
      region: '',
      city: 'Localhost',
      lat: 0,
      lon: 0,
      org: 'Private',
      query: ip,
    };
  }

  // Return cached result if still fresh
  const cached = CACHE.get(ip);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.data;
  }

  try {
    const res = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,lat,lon,query`,
      { timeout: 4000 }
    );
    const json = await res.json();

    if (json.status !== 'success') {
      throw new Error(json.message || 'ip-api returned non-success');
    }

    const data = {
      isp:         json.isp       || json.org || 'Unknown',
      country:     json.country   || '',
      countryCode: json.countryCode || '',
      region:      json.regionName || '',
      city:        json.city       || '',
      lat:         json.lat        || 0,
      lon:         json.lon        || 0,
      org:         json.org        || '',
      query:       json.query      || ip,
    };

    CACHE.set(ip, { ts: Date.now(), data });
    return data;
  } catch (err) {
    console.warn(`[ipLookup] Failed for ${ip}: ${err.message}`);
    return {
      isp: 'Unknown',
      country: '',
      countryCode: '',
      region: '',
      city: '',
      lat: 0,
      lon: 0,
      org: '',
      query: ip,
    };
  }
}

/**
 * Derive a stable network_id from IP + ISP.
 * We use the /24 prefix of the IP (first 3 octets) + ISP name so that
 * minor IP changes within the same subnet still produce the same ID.
 */
function buildNetworkId(ip, isp) {
  const prefix = ip.split('.').slice(0, 3).join('.') || ip; // handle IPv6 gracefully
  const raw = `${isp}|${prefix}`.toLowerCase().replace(/\s+/g, '');
  return simpleHash(raw);
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function isPrivateOrLoopback(ip) {
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === 'localhost'
  );
}

/** Deterministic 12-char hex hash (no crypto dependency needed for IDs). */
function simpleHash(str) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const n = (4294967296 * (2097151 & h2) + (h1 >>> 0)) >>> 0;
  return n.toString(16).padStart(12, '0');
}

module.exports = { lookupIP, buildNetworkId };
