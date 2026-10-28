'use strict';

const express = require('express');
const useragent = require('useragent');
const requestIp = require('request-ip');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const PORT = 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

const GEO_API_HOST = 'ip-api.com';
const GEO_API_FIELDS = [
  'status', 'message',
  'continent', 'continentCode',
  'country', 'countryCode',
  'region', 'regionName',
  'city', 'district', 'zip',
  'lat', 'lon', 'timezone', 'offset',
  'currency',
  'isp', 'org', 'as', 'asname',
  'reverse', 'mobile', 'proxy', 'hosting',
  'query',
].join(',');
const GEO_API_TIMEOUT_MS = 2500;

const GEO_CACHE_TTL_MS = 60 * 60 * 1000;
const GEO_CACHE_MAX = 5000;

const REQUEST_RATE_LIMIT = 100;
const REQUEST_RATE_WINDOW_MS = 60 * 1000;
const BODY_LIMIT = '10kb';

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
const logger = {
  info: (...a) => console.log(`[INFO]  ${new Date().toISOString()}`, ...a),
  warn: (...a) => console.warn(`[WARN]  ${new Date().toISOString()}`, ...a),
  error: (...a) => console.error(`[ERROR] ${new Date().toISOString()}`, ...a),
};

class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// IP helpers
// ---------------------------------------------------------------------------
function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string') return '';
  return ip.replace(/^::ffff:/, '').trim();
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip === '::1' || ip === 'localhost') return true;
  if (/^127\./.test(ip)) return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;
  if (/^f[cd]/i.test(ip)) return true;
  if (/^fe80:/i.test(ip)) return true;
  return false;
}

function resolveClientIp(req) {
  return normalizeIp(requestIp.getClientIp(req) || '');
}

// ---------------------------------------------------------------------------
// Cache + in-flight coalescing
// ---------------------------------------------------------------------------
const geoCache = new Map();
const geoInFlight = new Map();

function cacheGet(ip) {
  const entry = geoCache.get(ip);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    geoCache.delete(ip);
    return null;
  }
  geoCache.delete(ip);
  geoCache.set(ip, entry);
  return entry.value;
}

function cacheSet(ip, value) {
  if (geoCache.size >= GEO_CACHE_MAX) {
    const oldest = geoCache.keys().next().value;
    if (oldest !== undefined) geoCache.delete(oldest);
  }
  geoCache.set(ip, { value, expiresAt: Date.now() + GEO_CACHE_TTL_MS });
}

// ---------------------------------------------------------------------------
// ip-api.com client
// ---------------------------------------------------------------------------
function httpGetJson(host, path, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host, path, timeout: timeoutMs, headers: { 'User-Agent': 'client-info-app/1.0' } },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
          if (body.length > 64 * 1024) req.destroy(new Error('response_too_large'));
        });
        res.on('end', () => {
          if (res.statusCode !== 200) return reject(new Error(`geo_api_http_${res.statusCode}`));
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error('geo_api_bad_json'));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('geo_api_timeout')));
    req.on('error', reject);
  });
}

function shapeGeo(json) {
  return {
    status: json.status || null,
    message: json.message || null,

    continent: json.continent || null,
    continentCode: json.continentCode || null,

    country: json.country || null,
    countryCode: json.countryCode || null,

    region: json.region || null,
    regionName: json.regionName || null,

    city: json.city || null,
    district: json.district || null,
    zip: json.zip || null,

    latitude: typeof json.lat === 'number' ? json.lat : null,
    longitude: typeof json.lon === 'number' ? json.lon : null,
    timezone: json.timezone || null,
    offset: typeof json.offset === 'number' ? json.offset : null,
    currency: json.currency || null,

    isp: json.isp || null,
    org: json.org || null,
    as: json.as || null,
    asname: json.asname || null,
    reverse: json.reverse || null,

    mobile: json.mobile === true,
    proxy: json.proxy === true,
    hosting: json.hosting === true,

    query: json.query || null,
  };
}

async function fetchGeoFromApi(ip) {
  const path = `/json/${encodeURIComponent(ip)}?fields=${encodeURIComponent(GEO_API_FIELDS)}`;
  const json = await httpGetJson(GEO_API_HOST, path, GEO_API_TIMEOUT_MS);
  if (json.status !== 'success') {
    const msg = String(json.message || 'fail').toLowerCase().replace(/\s+/g, '_');
    throw new Error(`geo_api_${msg}`);
  }
  return shapeGeo(json);
}

function shortReason(err) {
  const m = String((err && err.message) || 'lookup_failed');
  if (m.includes('timeout')) return 'lookup_timeout';
  if (m.includes('private') || m.includes('reserved') || m.includes('invalid')) {
    return 'private_or_missing_ip';
  }
  if (m.includes('rate') || m.includes('limit')) return 'rate_limited';
  return 'lookup_failed';
}

async function lookupGeo(ip) {
  if (!ip) return { geo: null, reason: 'private_or_missing_ip' };
  if (isPrivateIp(ip)) return { geo: null, reason: 'private_or_missing_ip' };

  const cached = cacheGet(ip);
  if (cached) return { geo: cached, reason: null };

  if (geoInFlight.has(ip)) {
    try {
      return { geo: await geoInFlight.get(ip), reason: null };
    } catch (err) {
      return { geo: null, reason: shortReason(err) };
    }
  }

  const promise = (async () => {
    try {
      const geo = await fetchGeoFromApi(ip);
      cacheSet(ip, geo);
      return geo;
    } catch (err) {
      logger.warn(`Geo lookup failed for ${ip}:`, err.message);
      throw err;
    } finally {
      geoInFlight.delete(ip);
    }
  })();

  geoInFlight.set(ip, promise);

  try {
    return { geo: await promise, reason: null };
  } catch (err) {
    return { geo: null, reason: shortReason(err) };
  }
}

// ---------------------------------------------------------------------------
// Client data
// ---------------------------------------------------------------------------
function parseAgent(uaString) {
  const agent = useragent.parse(uaString || '');
  return {
    family: agent.family || 'Unknown',
    full: agent.toVersion ? agent.toVersion() : '',
    os: agent.os ? agent.os.toString() : 'Unknown',
    device: agent.device ? agent.device.toString() : 'Unknown',
    raw: uaString || '',
  };
}

async function collectClientData(req) {
  const clientIp = resolveClientIp(req);
  const userAgent = parseAgent(req.headers['user-agent']);
  const { geo, reason } = await lookupGeo(clientIp);

  const rawLang = req.headers['accept-language'] || '';
  const languages = rawLang
    .split(',')
    .map((s) => s.trim().split(';')[0])
    .filter(Boolean)
    .slice(0, 5);

  return {
    ipAddress: clientIp || 'Unknown',
    userAgent,
    ipGeo: geo,
    ipGeoReason: reason,
    request: {
      method: req.method,
      protocol: req.protocol,
      hostname: req.hostname,
      originalUrl: req.originalUrl,
      query: req.query,
    },
    client: {
      referrer: req.headers.referer || req.headers.referrer || 'Direct',
      languages,
      preferredLanguage: languages[0] || null,
    },
    requestedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// HTML rendering — enterprise grid layout
// ---------------------------------------------------------------------------
function escapeHtml(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const E = (v) => (v === null || v === undefined || v === '' ? '—' : escapeHtml(v));

function pill(label, tone = 'neutral') {
  return `<span class="pill pill-${tone}">${escapeHtml(label)}</span>`;
}

function field(label, value, opts = {}) {
  const { mono = false, cls = '' } = opts;
  return `<div class="field ${cls}">
    <div class="field-label">${escapeHtml(label)}</div>
    <div class="field-value${mono ? ' mono' : ''}">${value}</div>
  </div>`;
}

function card(title, body, extraClass = '') {
  return `<section class="card ${extraClass}">
    <header class="card-header"><h2>${escapeHtml(title)}</h2></header>
    <div class="card-body">${body}</div>
  </section>`;
}

function renderHtml(data) {
  const g = data.ipGeo || {};
  const ua = data.userAgent;
  const hasCoords = g.latitude != null && g.longitude != null;
  const geoNote = data.ipGeoReason
    ? pill(data.ipGeoReason, 'warn')
    : g.status === 'success'
      ? pill('resolved', 'ok')
      : pill('unknown', 'neutral');

  // --- Risk flags -------------------------------------------------------
  const riskFlags = [];
  if (g.proxy === true) riskFlags.push(pill('Proxy / VPN', 'danger'));
  if (g.hosting === true) riskFlags.push(pill('Hosting / Datacenter', 'danger'));
  if (g.mobile === true) riskFlags.push(pill('Mobile Network', 'info'));
  if (riskFlags.length === 0) riskFlags.push(pill('Residential / Clean', 'ok'));

  // --- Map --------------------------------------------------------------
  const mapBlock = hasCoords
    ? `<div class="map-wrap">
        <iframe width="100%" height="320" style="border:0;display:block" loading="lazy"
          referrerpolicy="no-referrer-when-downgrade"
          src="https://maps.google.com/maps?q=${g.latitude},${g.longitude}&z=10&output=embed"></iframe>
       </div>`
    : `<div class="map-empty">No coordinates available — map unavailable</div>`;

  // --- Network card -----------------------------------------------------
  const networkCard = card(
    'Network & Organization',
    `<div class="grid grid-2">
      ${field('ISP', E(g.isp))}
      ${field('Organization', E(g.org))}
      ${field('AS Number', E(g.as), { mono: true })}
      ${field('AS Name', E(g.asname))}
      ${field('Reverse DNS', E(g.reverse), { mono: true, cls: 'span-2' })}
      ${field('Reported Query IP', E(g.query), { mono: true })}
    </div>
    <div class="flags">${riskFlags.join('')}</div>`
  );

  // --- Geolocation card -------------------------------------------------
  const geoCard = card(
    'Geolocation',
    `<div class="grid grid-2">
      ${field('Continent', `${E(g.continent)} ${g.continentCode ? `<span class="sub">(${escapeHtml(g.continentCode)})</span>` : ''}`)}
      ${field('Country', `${E(g.country)} ${g.countryCode ? `<span class="sub">(${escapeHtml(g.countryCode)})</span>` : ''}`)}
      ${field('Region', `${E(g.regionName)} ${g.region ? `<span class="sub">(${escapeHtml(g.region)})</span>` : ''}`)}
      ${field('City', E(g.city))}
      ${field('District', E(g.district))}
      ${field('Postal Code', E(g.zip), { mono: true })}
      ${field('Latitude', g.latitude != null ? E(g.latitude) : '—', { mono: true })}
      ${field('Longitude', g.longitude != null ? E(g.longitude) : '—', { mono: true })}
      ${field('Timezone', E(g.timezone))}
      ${field('UTC Offset', g.offset != null ? `UTC${g.offset >= 0 ? '+' : ''}${g.offset / 3600}` : '—', { mono: true })}
      ${field('Currency', E(g.currency), { cls: 'span-2' })}
    </div>
    ${mapBlock}`
  );

  // --- Device card ------------------------------------------------------
  const deviceCard = card(
    'Device & Browser',
    `<div class="grid grid-2">
      ${field('Browser', `${E(ua.family)} ${E(ua.full)}`)}
      ${field('Operating System', E(ua.os))}
      ${field('Device Type', E(ua.device))}
      ${field('Preferred Language', E(data.client.preferredLanguage))}
      ${field('All Languages', data.client.languages.length ? data.client.languages.map(escapeHtml).join(', ') : '—', { cls: 'span-2' })}
      ${field('Referrer', E(data.client.referrer))}
      ${field('User-Agent', E(ua.raw), { mono: true, cls: 'span-2' })}
    </div>`
  );

  // --- Request card -----------------------------------------------------
  const requestCard = card(
    'Request',
    `<div class="grid grid-2">
      ${field('Client IP', E(data.ipAddress), { mono: true })}
      ${field('Method', E(data.request.method), { mono: true })}
      ${field('Protocol', E(data.request.protocol))}
      ${field('Hostname', E(data.request.hostname))}
      ${field('URL', E(data.request.originalUrl), { mono: true, cls: 'span-2' })}
      ${field('Requested At', E(data.requestedAt), { mono: true, cls: 'span-2' })}
    </div>`
  );

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Client Info · Diagnostic Report</title>
<style>
  :root {
    --bg: #0b0f17;
    --surface: #121826;
    --surface-2: #182033;
    --border: #232c42;
    --text: #e6ebf5;
    --muted: #8a94a8;
    --accent: #5b8def;
    --ok: #22c55e;
    --warn: #f59e0b;
    --danger: #ef4444;
    --info: #06b6d4;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Arial, sans-serif;
    background: radial-gradient(1200px 600px at 20% -10%, #17233c 0%, var(--bg) 55%);
    color: var(--text);
    min-height: 100vh;
    padding: 2rem 1.25rem 4rem;
  }
  .wrap { max-width: 1120px; margin: 0 auto; }

  /* Header */
  .page-header {
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: 1rem; flex-wrap: wrap; margin-bottom: 1.75rem;
  }
  .page-header h1 {
    font-size: 1.35rem; font-weight: 600; margin: 0 0 .25rem;
    letter-spacing: -0.01em;
  }
  .page-header p { margin: 0; color: var(--muted); font-size: .875rem; }
  .header-actions { display: flex; gap: .5rem; flex-wrap: wrap; }
  .btn {
    display: inline-flex; align-items: center; gap: .4rem;
    padding: .5rem .85rem; border-radius: 8px; font-size: .8125rem;
    border: 1px solid var(--border); background: var(--surface-2);
    color: var(--text); text-decoration: none; cursor: pointer;
    transition: background .15s, border-color .15s;
  }
  .btn:hover { background: #1f2a44; border-color: #2f3d5c; }
  .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  .btn-primary:hover { background: #4a7ce0; border-color: #4a7ce0; }

  /* Cards */
  .card {
    background: linear-gradient(180deg, var(--surface) 0%, #0f1626 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 1.25rem;
    box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset, 0 10px 30px -18px rgba(0,0,0,0.9);
  }
  .card-header {
    padding: .85rem 1.15rem;
    border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,0.015);
    display: flex; align-items: center; justify-content: space-between; gap: .75rem;
  }
  .card-header h2 {
    font-size: .8125rem; font-weight: 600; letter-spacing: .06em;
    text-transform: uppercase; color: #aab4c8; margin: 0;
  }
  .card-body { padding: 1.1rem 1.15rem 1.2rem; }

  /* Grid */
  .grid { display: grid; gap: .9rem 1.25rem; }
  .grid-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .span-2 { grid-column: span 2; }
  @media (max-width: 640px) {
    .grid-2 { grid-template-columns: 1fr; }
    .span-2 { grid-column: auto; }
  }

  /* Fields */
  .field { min-width: 0; }
  .field-label {
    font-size: .6875rem; text-transform: uppercase; letter-spacing: .07em;
    color: var(--muted); margin-bottom: .2rem; font-weight: 500;
  }
  .field-value {
    font-size: .9rem; color: var(--text); word-break: break-word;
    overflow-wrap: anywhere;
  }
  .field-value.mono { font-family: var(--mono); font-size: .84rem; color: #c9d4e8; }
  .sub { color: var(--muted); font-size: .8125rem; margin-left: .15rem; }

  /* Pills */
  .flags { display: flex; flex-wrap: wrap; gap: .4rem; margin-top: 1rem; }
  .pill {
    display: inline-flex; align-items: center;
    padding: .22rem .6rem; border-radius: 999px;
    font-size: .72rem; font-weight: 500; letter-spacing: .02em;
    border: 1px solid transparent;
  }
  .pill-ok      { background: rgba(34,197,94,0.1);  color: #6ee7a0; border-color: rgba(34,197,94,0.25); }
  .pill-warn    { background: rgba(245,158,11,0.1); color: #fbbf24; border-color: rgba(245,158,11,0.25); }
  .pill-danger  { background: rgba(239,68,68,0.1);  color: #f87171; border-color: rgba(239,68,68,0.25); }
  .pill-info    { background: rgba(6,182,212,0.1);  color: #67e8f9; border-color: rgba(6,182,212,0.25); }
  .pill-neutral { background: rgba(138,148,168,0.1);color: #aab4c8; border-color: rgba(138,148,168,0.25); }

  /* Map */
  .map-wrap {
    margin-top: 1.1rem;
    border: 1px solid var(--border);
    border-radius: 10px; overflow: hidden;
    background: #0a0f1a;
  }
  .map-empty {
    margin-top: 1.1rem; padding: 1.5rem 1rem; text-align: center;
    color: var(--muted); font-size: .85rem;
    border: 1px dashed var(--border); border-radius: 10px;
  }

  /* Footer */
  .footer {
    display: flex; justify-content: space-between; align-items: center;
    gap: .75rem; flex-wrap: wrap;
    color: var(--muted); font-size: .78rem; margin-top: 1.75rem;
  }
  .footer a { color: var(--accent); text-decoration: none; }
  .footer a:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="wrap">

  <header class="page-header">
    <div>
      <h1>Client Diagnostic Report</h1>
      <p>Full request, device, and network intelligence · ${escapeHtml(data.requestedAt)}</p>
    </div>
    <div class="header-actions">
      <a class="btn btn-primary" href="?format=json">View JSON</a>
      <a class="btn" href="/">Refresh</a>
    </div>
  </header>

  ${card(
    'Summary',
    `<div class="grid grid-2">
      ${field('Client IP', E(data.ipAddress), { mono: true })}
      ${field('IP Resolution', geoNote)}
      ${field('Location', [g.city, g.regionName, g.country].filter(Boolean).map(escapeHtml).join(', ') || '—', { cls: 'span-2' })}
      ${field('Network', [g.isp, g.as].filter(Boolean).map(escapeHtml).join(' · ') || '—', { cls: 'span-2' })}
    </div>`
  )}

  ${geoCard}
  ${networkCard}
  ${deviceCard}
  ${requestCard}

  <footer class="footer">
    <span>ip-api.com · cached ${Math.round(GEO_CACHE_TTL_MS / 60000)} min · node ${escapeHtml(process.version)}</span>
    <span><a href="?format=json">JSON</a> · <a href="/health">Health</a></span>
  </footer>

</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        frameSrc: ['https://*.google.com', 'https://*.googleapis.com', 'https://*.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);

app.use(
  rateLimit({
    windowMs: REQUEST_RATE_WINDOW_MS,
    max: REQUEST_RATE_LIMIT,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { success: false, error: { code: 'RATE_LIMIT', message: 'Too many requests' } },
  })
);

app.use(express.json({ limit: BODY_LIMIT }));
app.use(cors({ origin: NODE_ENV === 'production' ? false : true }));

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.info(
      `${req.method} ${req.originalUrl} → ${res.statusCode} (${Date.now() - start}ms) ip=${resolveClientIp(req) || 'unknown'}`
    );
  });
  next();
});

app.get('/', async (req, res, next) => {
  try {
    const data = await collectClientData(req);
    const wantsJson = req.query.format === 'json' || req.accepts(['html', 'json']) === 'json';
    if (wantsJson) return res.json({ success: true, data });
    res.type('html').send(renderHtml(data));
  } catch (err) {
    next(err);
  }
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.use((req, res) => {
  if (req.accepts('json') && !req.accepts('html')) {
    return res
      .status(404)
      .json({ success: false, error: { code: 'NOT_FOUND', message: 'Route not found' } });
  }
  res.status(404).type('html').send('<h1>404</h1>');
});

app.use((err, req, res, _next) => {
  const known = err instanceof AppError;
  const statusCode = known ? err.statusCode : 500;
  const code = known ? err.code : 'INTERNAL_ERROR';
  logger.error(`${req.method} ${req.originalUrl} failed:`, err.message);

  const wantsJson = req.query.format === 'json' || req.accepts(['html', 'json']) === 'json';
  if (wantsJson) {
    return res.status(statusCode).json({
      success: false,
      error: { code, message: known ? err.message : 'Internal server error' },
    });
  }
  res
    .status(statusCode)
    .type('html')
    .send(
      `<!DOCTYPE html><meta charset="UTF-8"><title>Error</title>` +
        `<h1>Error ${statusCode}</h1><p>${escapeHtml(code)}</p>` +
        `${known ? `<p>${escapeHtml(err.message)}</p>` : ''}<p><a href="/">Back</a></p>`
    );
});

// ---------------------------------------------------------------------------
// Start / shutdown
// ---------------------------------------------------------------------------
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server listening on :${PORT} (env=${NODE_ENV})`);
});

function shutdown(signal) {
  logger.info(`${signal} received — shutting down`);
  server.close((err) => {
    if (err) {
      logger.error('Shutdown error:', err);
      process.exit(1);
    }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (reason) => logger.error('Unhandled rejection:', reason));
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception:', err);
  shutdown('uncaughtException');
});
