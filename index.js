'use strict';

const express = require('express');
const cors = require('cors');
const { getLocation } = require('ip-based-location');
const { UAParser } = require('ua-parser-js');
require('dotenv').config();

const PORT = parseInt(process.env.PORT, 10) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const LOCATION_TIMEOUT = parseInt(process.env.LOCATION_TIMEOUT_MS, 10) || 4000;
const FALLBACK_IP = process.env.FALLBACK_IP || '8.8.8.8';
const IS_DEV = (process.env.NODE_ENV || 'development') === 'development';

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

function extractClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) {
    return normalizeIp(forwarded.split(',')[0]);
  }
  return normalizeIp(req.ip || req.socket?.remoteAddress || '');
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

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new AppError(`${label} timed out after ${ms}ms`, 504, 'UPSTREAM_TIMEOUT')),
      ms
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function resolveLocation(ip) {
  const result = { location: null, source: null, reason: null };
  if (!ip) {
    result.reason = 'no_ip';
    return result;
  }

  let lookupIp = ip;
  if (isPrivateIp(ip)) {
    if (IS_DEV) {
      result.reason = 'private_ip_fallback';
      lookupIp = FALLBACK_IP;
    } else {
      result.reason = 'private_ip';
      return result;
    }
  }

  try {
    const raw = await withTimeout(getLocation(lookupIp), LOCATION_TIMEOUT, 'location lookup');
    if (!raw || typeof raw !== 'object' || !Object.keys(raw).length) {
      result.reason = 'empty_result';
      return result;
    }
    result.location = {
      country: raw.country || null,
      countryCode: raw.countryCode || null,
      region: raw.region || null,
      city: raw.city || null,
      postalCode: raw.postalCode || null,
      latitude: raw.latitude ?? null,
      longitude: raw.longitude ?? null,
      timezone: raw.timezone || null,
      isp: raw.isp || null,
    };
    result.source = lookupIp === ip ? 'client_ip' : 'fallback_ip';
    return result;
  } catch (err) {
    logger.warn('Location lookup failed:', err.message);
    result.reason = err.code || 'lookup_failed';
    return result;
  }
}

function parseUserAgent(uaString) {
  const r = new UAParser(uaString || '').getResult();
  return {
    browser: [r.browser.name, r.browser.version].filter(Boolean).join(' ') || 'Unknown',
    os: [r.os.name, r.os.version].filter(Boolean).join(' ') || 'Unknown',
    device: r.device.type || 'desktop',
    raw: uaString || '',
  };
}

function buildApproxAddress(loc) {
  if (!loc) return null;
  const parts = [loc.city, loc.region, loc.postalCode, loc.country].filter(Boolean);
  return parts.length ? parts.join(', ') : null;
}

async function collectClientData(req) {
  const clientIp = extractClientIp(req);
  const ua = parseUserAgent(req.headers['user-agent']);
  const loc = await resolveLocation(clientIp);

  return {
    ip: clientIp || 'Unknown',
    location: loc.location,
    locationMeta: {
      source: loc.source,
      reason: loc.reason,
      approximateAddress: buildApproxAddress(loc.location),
    },
    userAgent: ua,
    referrer: req.headers.referer || req.headers.referrer || 'Direct',
    queryParams: req.query,
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

const EMPTY = '<span class="empty">Not available</span>';
const v = (x) => (x === null || x === undefined || x === '' ? EMPTY : escapeHtml(x));

function renderHtml(data) {
  const loc = data.location || {};
  const ua = data.userAgent;
  const meta = data.locationMeta;
  const notice = meta.reason
    ? `<div class="notice">${escapeHtml(meta.reason)}</div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Client Info Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:linear-gradient(135deg,#f5f7fa 0%,#e4e8ec 100%);min-height:100vh;display:flex;justify-content:center;align-items:flex-start;padding:2rem}
.card{background:#fff;border-radius:16px;box-shadow:0 8px 40px rgba(0,0,0,.08);max-width:680px;width:100%;overflow:hidden}
.header{background:linear-gradient(135deg,#1e3c72 0%,#2a5298 100%);color:#fff;padding:1.5rem 2rem}
.header h1{font-size:1.35rem;font-weight:600}
.header p{font-size:.85rem;opacity:.8;margin-top:.25rem}
.body{padding:1.75rem 2rem 2rem}
.section{margin-bottom:1.5rem}
.section:last-child{margin-bottom:0}
.section-title{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:#8899aa;margin-bottom:.75rem;font-weight:600}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
.item{background:#f8fafc;border-radius:10px;padding:.75rem 1rem}
.item.full{grid-column:1/-1}
.label{font-size:.7rem;color:#8899aa;text-transform:uppercase;letter-spacing:.5px;margin-bottom:.2rem}
.value{font-size:.95rem;color:#1a202c;font-weight:500;word-break:break-word}
.value.mono{font-family:"SF Mono",Monaco,monospace;font-size:.82rem;color:#4a5568}
.badge{display:inline-block;background:#ebf8ff;color:#2b6cb0;padding:.15rem .6rem;border-radius:6px;font-size:.85rem;font-weight:600}
.empty{color:#a0aec0;font-style:italic;font-weight:400}
.notice{margin-top:.5rem;font-size:.75rem;color:#b7791f;background:#fffaf0;border:1px solid #feebc8;border-radius:6px;padding:.35rem .6rem;display:inline-block}
.footer{text-align:center;padding:.75rem;font-size:.75rem;color:#a0aec0;border-top:1px solid #edf2f7}
.footer a{color:#2b6cb0;text-decoration:none}
@media(max-width:520px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="card">
<div class="header">
<h1>🌐 Client Information</h1>
<p>IP-based location · approximate · city/postal level</p>
</div>
<div class="body">

<div class="section">
<div class="section-title">Location</div>
<div class="grid">
<div class="item"><div class="label">IP Address</div><div class="value"><span class="badge">${escapeHtml(data.ip)}</span></div></div>
<div class="item"><div class="label">Approx. Address</div><div class="value">${v(meta.approximateAddress)}</div></div>
<div class="item"><div class="label">Country</div><div class="value">${loc.country ? `${escapeHtml(loc.country)} (${escapeHtml(loc.countryCode || '')})` : EMPTY}</div></div>
<div class="item"><div class="label">Region</div><div class="value">${v(loc.region)}</div></div>
<div class="item"><div class="label">City</div><div class="value">${v(loc.city)}</div></div>
<div class="item"><div class="label">Postal Code</div><div class="value">${v(loc.postalCode)}</div></div>
<div class="item"><div class="label">Timezone</div><div class="value">${v(loc.timezone)}</div></div>
<div class="item"><div class="label">ISP</div><div class="value">${v(loc.isp)}</div></div>
<div class="item"><div class="label">Latitude</div><div class="value mono">${loc.latitude != null ? escapeHtml(loc.latitude) : EMPTY}</div></div>
<div class="item"><div class="label">Longitude</div><div class="value mono">${loc.longitude != null ? escapeHtml(loc.longitude) : EMPTY}</div></div>
</div>
${notice}
</div>

<div class="section">
<div class="section-title">Device</div>
<div class="grid">
<div class="item"><div class="label">Browser</div><div class="value">${escapeHtml(ua.browser)}</div></div>
<div class="item"><div class="label">Operating System</div><div class="value">${escapeHtml(ua.os)}</div></div>
<div class="item"><div class="label">Device Type</div><div class="value">${escapeHtml(ua.device)}</div></div>
<div class="item"><div class="label">Referrer</div><div class="value">${escapeHtml(data.referrer)}</div></div>
<div class="item full"><div class="label">Raw User Agent</div><div class="value mono">${escapeHtml(ua.raw) || EMPTY}</div></div>
</div>
</div>

</div>
<div class="footer"><a href="?format=json">View as JSON</a> · Location data is approximate</div>
</div>
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
    logger.info(`${req.method} ${req.originalUrl} → ${res.statusCode} (${Date.now() - start}ms) ip=${extractClientIp(req)}`);
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
  res.json({ status: 'ok', uptime: process.uptime(), env: IS_DEV ? 'development' : 'production' });
});

app.use((req, res) => {
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Route not found' } });
  }
  res.status(404).type('html').send('<h1>404 — Not Found</h1>');
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
  res.status(statusCode).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Error ${statusCode}</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f7fafc}.box{background:#fff;padding:2rem 2.5rem;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center}h1{color:#c53030;font-size:1.5rem;margin:0 0 .5rem}p{color:#4a5568;margin:.25rem 0}a{color:#2b6cb0}</style></head>
<body><div class="box"><h1>Error ${statusCode}</h1><p>${escapeHtml(code)}</p>${known ? `<p>${escapeHtml(err.message)}</p>` : ''}<p><a href="/">← Back</a></p></div></body></html>`);
});

const server = app.listen(PORT, () => {
  logger.info(`Server running at http://localhost:${PORT} (env=${IS_DEV ? 'development' : 'production'})`);
});

function shutdown(signal) {
  logger.info(`${signal} received — shutting down`);
  server.close((err) => {
    if (err) {
      logger.error('Error during shutdown:', err);
      process.exit(1);
    }
    logger.info('Server closed');
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
