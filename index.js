'use strict';

const express = require('express');
const useragent = require('useragent');
const requestIp = require('request-ip');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');

// ---------------------------------------------------------------------------
// Constants — single source of truth for tuning
// ---------------------------------------------------------------------------
const PORT = 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

const GEO_API_HOST = 'ip-api.com';           // free tier: HTTP only, 45 req/min
const GEO_API_FIELDS = 'status,message,country,regionName,city,timezone,lat,lon,query';
const GEO_API_TIMEOUT_MS = 2500;

const GEO_CACHE_TTL_MS = 60 * 60 * 1000;     // 1 hour — IPs rarely move
const GEO_CACHE_MAX = 5000;                  // LRU cap

const REQUEST_RATE_LIMIT = 100;              // per minute per IP
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
// TTL + LRU cache, and in-flight coalescing
// ---------------------------------------------------------------------------
const geoCache = new Map();     // ip -> { value, expiresAt }
const geoInFlight = new Map();  // ip -> Promise<geo>

function cacheGet(ip) {
  const entry = geoCache.get(ip);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    geoCache.delete(ip);
    return null;
  }
  // refresh LRU position
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

async function fetchGeoFromApi(ip) {
  const path = `/json/${encodeURIComponent(ip)}?fields=${encodeURIComponent(GEO_API_FIELDS)}`;
  const json = await httpGetJson(GEO_API_HOST, path, GEO_API_TIMEOUT_MS);

  if (json.status !== 'success') {
    const msg = String(json.message || 'fail').toLowerCase().replace(/\s+/g, '_');
    throw new Error(`geo_api_${msg}`);
  }

  return {
    country: json.country || null,
    region: json.regionName || null,
    city: json.city || null,
    timezone: json.timezone || null,
    latitude: typeof json.lat === 'number' ? json.lat : null,
    longitude: typeof json.lon === 'number' ? json.lon : null,
  };
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

/**
 * Returns { geo, reason }:
 *   geo    = { country, region, city, timezone, latitude, longitude } | null
 *   reason = null on success, else a short tag explaining why geo is null
 */
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
    },
    client: {
      referrer: req.headers.referer || req.headers.referrer || 'Direct',
      preferredLanguage: languages[0] || null,
    },
    requestedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// HTML rendering
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

const E = (v) => (v === null || v === undefined || v === '' ? '' : escapeHtml(v));

function renderHtml(data) {
  const g = data.ipGeo || {};
  const ua = data.userAgent;
  const geoNote = data.ipGeoReason ? ` (${E(data.ipGeoReason)})` : '';
  const hasCoords = g.latitude != null && g.longitude != null;

  const mapBlock = hasCoords
    ? `<div style="margin-top:.75rem;border:1px solid #e5e5e5;border-radius:4px;overflow:hidden">
  <iframe width="100%" height="300" style="border:0;display:block" loading="lazy" referrerpolicy="no-referrer-when-downgrade"
    src="https://maps.google.com/maps?q=${g.latitude},${g.longitude}&z=10&output=embed"></iframe>
</div>`
    : `<p class="muted" style="margin-top:.75rem">No coordinates available for map</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Client Info</title>
<style>
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:#222;background:#fff;max-width:720px;margin:2rem auto;padding:0 1rem}
h2{font-size:1rem;margin:1.5rem 0 .5rem;color:#555;border-bottom:1px solid #e5e5e5;padding-bottom:.25rem}
table{width:100%;border-collapse:collapse}
td{padding:.35rem .5rem;vertical-align:top;border-bottom:1px solid #f0f0f0}
td:first-child{color:#666;width:160px;white-space:nowrap}
code{font-family:ui-monospace,Menlo,monospace;font-size:.9em;background:#f7f7f7;padding:1px 4px;border-radius:3px;word-break:break-all}
a{color:#06c}.muted{color:#999;font-size:.9em}
</style>
</head>
<body>
<h2>Request</h2>
<table>
<tr><td>IP</td><td><code>${E(data.ipAddress)}</code></td></tr>
<tr><td>Method</td><td>${E(data.request.method)}</td></tr>
<tr><td>URL</td><td><code>${E(data.request.originalUrl)}</code></td></tr>
<tr><td>Referrer</td><td>${E(data.client.referrer)}</td></tr>
<tr><td>Language</td><td>${E(data.client.preferredLanguage || '')}</td></tr>
</table>
<h2>IP Location <span class="muted">(approximate)${geoNote}</span></h2>
<table>
<tr><td>Country</td><td>${E(g.country)}</td></tr>
<tr><td>Region</td><td>${E(g.region)}</td></tr>
<tr><td>City</td><td>${E(g.city)}</td></tr>
<tr><td>Timezone</td><td>${E(g.timezone)}</td></tr>
<tr><td>Latitude</td><td>${g.latitude != null ? E(g.latitude) : ''}</td></tr>
<tr><td>Longitude</td><td>${g.longitude != null ? E(g.longitude) : ''}</td></tr>
</table>
${mapBlock}
<h2>Device</h2>
<table>
<tr><td>Browser</td><td>${E(ua.family)} ${E(ua.full)}</td></tr>
<tr><td>OS</td><td>${E(ua.os)}</td></tr>
<tr><td>Device</td><td>${E(ua.device)}</td></tr>
<tr><td>User-Agent</td><td><code>${E(ua.raw)}</code></td></tr>
</table>
<div class="muted" style="margin-top:2rem"><a href="?format=json">JSON</a> · ${E(data.requestedAt)}</div>
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
