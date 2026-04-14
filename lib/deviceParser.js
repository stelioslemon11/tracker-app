/**
 * lib/deviceParser.js
 * Parses the User-Agent string into structured browser / OS / device info.
 */

const UAParser = require('ua-parser-js');

/**
 * @param {string} userAgent
 * @returns {{
 *   browser: string, browser_version: string,
 *   os: string, os_version: string,
 *   device_type: string
 * }}
 */
function parseUA(userAgent) {
  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  const browser         = result.browser.name  || 'Unknown';
  const browser_version = result.browser.major || '';
  const os              = result.os.name        || 'Unknown';
  const os_version      = result.os.version     || '';

  // ua-parser-js exposes device.type for mobile/tablet; desktop is undefined
  const raw_type  = result.device.type;
  const device_type = raw_type
    ? raw_type.charAt(0).toUpperCase() + raw_type.slice(1)
    : 'Desktop';

  return { browser, browser_version, os, os_version, device_type };
}

module.exports = { parseUA };
