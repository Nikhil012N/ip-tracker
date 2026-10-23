'use strict';

const express = require('express');
const useragent = require('useragent');
const geoip = require('geoip-lite');
const requestIp = require('request-ip');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const PORT = parseInt(process.env.PORT, 10) || 3000;
const GOOGLE_MAPS_KEY = process.env.GOOGLE_MAPS_KEY || '';

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
  if (/^fc|^fd/.test(ip)) return true;
  if (/^fe80:/.test(ip)) return true;
  return false;
}

function resolveClientIp(req) {
  return normalizeIp(requestIp.getClientIp(req) || '');
}

function parseAgent(uaString) {
  const agent = useragent.parse(uaString || '');
  return {
    family: agent.family || 'Unknown',
    major: agent.major || '',
    minor: agent.minor || '',
    patch: agent.patch || '',
    full: agent.toVersion ? agent.toVersion() : '',
    os: agent.os ? agent.os.toString() : 'Unknown',
    device: agent.device ? agent.device.toString() : 'Unknown',
    raw: uaString || '',
  };
}

function lookupGeo(ip) {
  if (!ip || isPrivateIp(ip)) return { geo: null, reason: 'private_or_missing_ip' };
  try {
    const g = geoip.lookup(ip);
    if (!g) return { geo: null, reason: 'not_in_database' };
    return {
      geo: {
        country: g.country || null,
        region: g.region || null,
        city: g.city || null,
        timezone: g.timezone || null,
        latitude: Array.isArray(g.ll) ? g.ll[0] : null,
        longitude: Array.isArray(g.ll) ? g.ll[1] : null,
      },
      reason: null,
    };
  } catch (err) {
    logger.warn('GeoIP lookup failed:', err.message);
    return { geo: null, reason: 'lookup_failed' };
  }
}

function collectClientData(req) {
  const clientIp = resolveClientIp(req);
  const userAgent = parseAgent(req.headers['user-agent']);
  const { geo, reason } = lookupGeo(clientIp);

  const rawLang = req.headers['accept-language'] || '';
  const languages = rawLang.split(',').map(s => s.trim().split(';')[0]).filter(Boolean).slice(0, 5);

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

  let mapBlock = '';
  if (hasCoords) {
    const embedUrl = `https://maps.google.com/maps?q=${g.latitude},${g.longitude}&z=10&output=embed`;
    mapBlock = `
<div style="margin-top:.75rem;border:1px solid #e5e5e5;border-radius:4px;overflow:hidden">
  <iframe width="100%" height="300" style="border:0;display:block" loading="lazy" referrerpolicy="no-referrer-when-downgrade" src="${embedUrl}"></iframe>
</div>`;
  } else {
    mapBlock = `<p class="muted" style="margin-top:.75rem">No coordinates available for map</p>`;
  }

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

const app = express();

// Always trust proxy - but trust exactly 1 hop (safest interpretation)
app.set('trust proxy', 1);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // needed for inline script
      frameSrc: ["https://maps.google.com"],
      imgSrc: ["'self'", "data:", "https:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
}));

// Rate limiting: 100 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, error: { code: 'RATE_LIMIT', message: 'Too many requests' } },
});
app.use(limiter);

// Body size limit
app.use(express.json({ limit: '10kb' }));

// CORS - restrict to same origin in production
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : true,
}));

// Access log
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.info(`${req.method} ${req.originalUrl} → ${res.statusCode} (${Date.now() - start}ms) ip=${resolveClientIp(req) || 'unknown'}`);
  });
  next();
});

app.get('/', (req, res, next) => {
  try {
    const data = collectClientData(req);
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

// 404 handler
app.use((req, res) => {
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Route not found' } });
  }
  res.status(404).type('html').send('<h1>404</h1>');
});

// Global error handler - never leaks stack traces
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
  res.status(statusCode).type('html').send(
    `<!DOCTYPE html><meta charset="UTF-8"><title>Error</title>` +
    `<h1>Error ${statusCode}</h1><p>${escapeHtml(code)}</p>` +
    `${known ? `<p>${escapeHtml(err.message)}</p>` : ''}<p><a href="/">Back</a></p>`
  );
});

const server = app.listen(PORT, () => {
  logger.info(`Server running at http://localhost:${PORT}`);
});

function shutdown(signal) {
  logger.info(`${signal} received — shutting down`);
  server.close((err) => {
    if (err) { logger.error('Shutdown error:', err); process.exit(1); }
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
