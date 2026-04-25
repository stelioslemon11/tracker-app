/**
 * public/collector.js
 *
 * Client-side data collection module.
 * Runs in the browser, gathers all available signals, and POSTs them to
 * /api/visit.  Returns the server response (correlation result).
 *
 * Fingerprinting techniques used:
 *   1. Canvas fingerprint   — renders text + shapes; pixel buffer hashed
 *   2. WebGL fingerprint    — renderer/vendor strings + pixel render
 *   3. Audio fingerprint    — OfflineAudioContext oscillator output hashed
 *   4. Persistent device_id — UUID stored in both cookie AND localStorage
 *      (if one is cleared, the other acts as a backup)
 */

/* ─── Persistent device_id ──────────────────────────────────────────────────── */

function getOrCreateDeviceId() {
  const KEY = '__tid__';

  // Try localStorage first
  let id = null;
  try { id = localStorage.getItem(KEY); } catch (_) {}

  // Then cookie
  if (!id) {
    const match = document.cookie.match(new RegExp('(?:^|;\\s*)' + KEY + '=([^;]+)'));
    if (match) id = match[1];
  }

  // Create a new UUID v4 if neither existed
  if (!id) {
    id = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  // Persist in both stores (1-year expiry for cookie)
  try { localStorage.setItem(KEY, id); } catch (_) {}
  try {
    const exp = new Date(Date.now() + 365 * 86400 * 1000).toUTCString();
    document.cookie = `${KEY}=${id}; expires=${exp}; path=/; SameSite=Lax`;
  } catch (_) {}

  return id;
}

/* ─── Canvas fingerprint ─────────────────────────────────────────────────────── */

function canvasFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    canvas.width  = 220;
    canvas.height = 30;
    const ctx = canvas.getContext('2d');

    ctx.textBaseline = 'top';
    ctx.font         = '14px Arial';
    ctx.fillStyle    = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle    = '#069';
    ctx.fillText('Cwm fjordbank glyphs vext quiz', 2, 15);
    ctx.fillStyle    = 'rgba(102,204,0,0.7)';
    ctx.fillText('Cwm fjordbank glyphs vext quiz', 4, 17);

    return hashString(canvas.toDataURL());
  } catch (_) {
    return null;
  }
}

/* ─── WebGL fingerprint ──────────────────────────────────────────────────────── */

function webglFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const gl     = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;

    const dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
    const vendor  = dbgInfo ? gl.getParameter(dbgInfo.UNMASKED_VENDOR_WEBGL)   : '';
    const renderer= dbgInfo ? gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL) : '';

    // Also render a small scene for pixel-level uniqueness
    const vs = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vs, 'attribute vec2 p;void main(){gl_Position=vec4(p,0,1);}');
    gl.compileShader(vs);

    const fs = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fs, 'precision mediump float;void main(){gl_FragColor=vec4(0.3,0.5,0.7,1);}');
    gl.compileShader(fs);

    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    gl.useProgram(prog);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1,1,-1,-1,1]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    const px = new Uint8Array(4);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);

    return hashString(`${vendor}|${renderer}|${px.join(',')}`);
  } catch (_) {
    return null;
  }
}

/* ─── Audio fingerprint ──────────────────────────────────────────────────────── */

function audioFingerprint() {
  return new Promise(resolve => {
    try {
      const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AudioCtx) return resolve(null);

      const ctx  = new AudioCtx(1, 44100, 44100);
      const osc  = ctx.createOscillator();
      const comp = ctx.createDynamicsCompressor();

      osc.type = 'triangle';
      osc.frequency.value = 10000;

      [['threshold',-50],['knee',40],['ratio',12],['reduction',-20],['attack',0],['release',0.25]]
        .forEach(([k,v]) => { try { comp[k].value = v; } catch(_){} });

      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);

      ctx.oncomplete = e => {
        try {
          const buf = e.renderedBuffer.getChannelData(0);
          let sum = 0;
          for (let i = 4500; i < 5000; i++) sum += Math.abs(buf[i]);
          resolve(hashString(sum.toString()));
        } catch (_) {
          resolve(null);
        }
      };

      ctx.startRendering();
      setTimeout(() => resolve(null), 2000); // timeout guard
    } catch (_) {
      resolve(null);
    }
  });
}

/* ─── Environment signals ────────────────────────────────────────────────────── */

function collectEnvironment() {
  const nav = navigator;
  return {
    screen_resolution: `${screen.width}x${screen.height}`,
    color_depth:       screen.colorDepth,
    timezone:          Intl.DateTimeFormat().resolvedOptions().timeZone,
    language:          nav.language || nav.userLanguage || '',
    platform:          nav.platform || '',
    cpu_cores:         nav.hardwareConcurrency || null,
    memory_gb:         nav.deviceMemory        || null,
    touch_support:     ('ontouchstart' in window) || navigator.maxTouchPoints > 0,
  };
}

/* ─── Hash helper ────────────────────────────────────────────────────────────── */

function hashString(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h  = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/* ─── Main: collect + submit ─────────────────────────────────────────────────── */

async function collectAndSubmit(extraPayload = {}) {
  const device_id    = getOrCreateDeviceId();
  const env          = collectEnvironment();
  const canvasHash   = canvasFingerprint();
  const webglHash    = webglFingerprint();
  const audioHash    = await audioFingerprint();

  // Combine canvas + webGL + audio into a single probabilistic fingerprint_id
  const rawFP        = [canvasHash, webglHash, audioHash].filter(Boolean).join('|');
  const fingerprint_id = rawFP ? hashString(rawFP) : null;

  const payload = {
    device_id,
    fingerprint_id,
    ...env,
    ...extraPayload,   // lan_peers, local_ip, etc.
  };

  const response = await fetch('/api/visit', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || `HTTP ${response.status}`);
  }

  return response.json();
}

// Export for use in index.html
window.TrackerCollector = { collectAndSubmit };
