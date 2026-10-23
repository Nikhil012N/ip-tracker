'use strict';

const express = require('express');
const useragent = require('useragent');
const geoip = require('geoip-lite');
const requestIp = require('request-ip');
const cors = require('cors');
require('dotenv').config();

const PORT = parseInt(process.env.PORT, 10) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY !== 'false';

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
        metro: g.metro ?? null,
        area: g.area ?? null,
        eu: g.eu === '1',
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
  const languages = rawLang.split(',').map(s => s.trim().split(';')[0]).filter(Boolean);

  return {
    ipAddress: clientIp || 'Unknown',
    userAgent,
    geoLocation: geo,
    geoMeta: { reason, source: 'geoip-lite (local)' },
    request: {
      method: req.method,
      protocol: req.protocol,
      hostname: req.hostname,
      path: req.path,
      originalUrl: req.originalUrl,
      query: req.query,
      secure: req.secure,
      xhr: req.xhr,
      ips: req.ips || [],
    },
    client: {
      referrer: req.headers.referer || req.headers.referrer || 'Direct',
      languages,
      preferredLanguage: languages[0] || null,
      acceptEncoding: req.headers['accept-encoding'] || null,
    },
    headers: req.headers,
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

function renderHtml(data) {
  const g = data.geoLocation || {};
  const ua = data.userAgent;
  const geoNote = data.geoMeta.reason
    ? `<tr><td>Note</td><td>${escapeHtml(data.geoMeta.reason)}</td></tr>`
    : '';

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
a{color:#06c}
.foot{margin-top:2rem;font-size:.85em;color:#888}
</style>
</head>
<body>
<h2>Request</h2>
<table>
<tr><td>IP</td><td><code>${escapeHtml(data.ipAddress)}</code></td></tr>
<tr><td>Method</td><td>${escapeHtml(data.request.method)}</td></tr>
<tr><td>URL</td><td><code>${escapeHtml(data.request.originalUrl)}</code></td></tr>
<tr><td>Host</td><td>${escapeHtml(data.request.hostname)}</td></tr>
<tr><td>Protocol</td><td>${escapeHtml(data.request.protocol)}</td></tr>
<tr><td>Referrer</td><td>${escapeHtml(data.client.referrer)}</td></tr>
<tr><td>Language</td><td>${escapeHtml(data.client.preferredLanguage || '')}</td></tr>
</table>

<h2>Location</h2>
<table>
<tr><td>Country</td><td>${escapeHtml(g.country || '')}</td></tr>
<tr><td>Region</td><td>${escapeHtml(g.region || '')}</td></tr>
<tr><td>City</td><td>${escapeHtml(g.city || '')}</td></tr>
<tr><td>Timezone</td><td>${escapeHtml(g.timezone || '')}</td></tr>
<tr><td>Latitude</td><td>${g.latitude != null ? escapeHtml(g.latitude) : ''}</td></tr>
<tr><td>Longitude</td><td>${g.longitude != null ? escapeHtml(g.longitude) : ''}</td></tr>
${geoNote}
</table>

<h2>Device</h2>
<table>
<tr><td>Browser</td><td>${escapeHtml(ua.family)} ${escapeHtml(ua.full)}</td></tr>
<tr><td>OS</td><td>${escapeHtml(ua.os)}</td></tr>
<tr><td>Device</td><td>${escapeHtml(ua.device)}</td></tr>
<tr><td>User-Agent</td><td><code>${escapeHtml(ua.raw)}</code></td></tr>
</table>

<div class="foot"><a href="?format=json">JSON</a> · ${escapeHtml(data.requestedAt)}</div>
</body>
</html>`;
}

const app = express();
if (TRUST_PROXY) app.set('trust proxy', true);
app.use(cors());
app.use(express.json({ limit: '10kb' }));

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

app.use((req, res) => {
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Route not found' } });
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
