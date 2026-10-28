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
// HTML rendering — shadcn/ui visual language, fully responsive
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

function field(label, value, opts = {}) {
  const { mono = false, cls = '' } = opts;
  return `<div class="field ${cls}">
    <dt class="field-label">${escapeHtml(label)}</dt>
    <dd class="field-value${mono ? ' mono' : ''}">${value}</dd>
  </div>`;
}

function card(title, body, extraClass = '') {
  return `<section class="card ${extraClass}">
    <div class="card-header">
      <h2 class="card-title">${escapeHtml(title)}</h2>
    </div>
    <div class="card-content">${body}</div>
  </section>`;
}

function renderHtml(data) {
  const g = data.ipGeo || {};
  const ua = data.userAgent;
  const hasCoords = g.latitude != null && g.longitude != null;

  const statusText = data.ipGeoReason
    ? data.ipGeoReason
    : g.status === 'success'
      ? 'resolved'
      : 'unknown';

  const mapBlock = hasCoords
    ? `<div class="map-wrap">
        <iframe
          title="IP location map"
          width="100%"
          height="100%"
          style="border:0;display:block"
          loading="lazy"
          referrerpolicy="no-referrer-when-downgrade"
          src="https://maps.google.com/maps?q=${g.latitude},${g.longitude}&z=10&output=embed"></iframe>
       </div>`
    : `<div class="map-empty">No coordinates available for map</div>`;

  const summaryCard = card(
    'Summary',
    `<dl class="grid grid-2">
      ${field('Client IP', E(data.ipAddress), { mono: true })}
      ${field('IP resolution', `<span class="badge">${escapeHtml(statusText)}</span>`)}
      ${field('Location', [g.city, g.regionName, g.country].filter(Boolean).map(escapeHtml).join(', ') || '—', { cls: 'span-2' })}
      ${field('Network', [g.isp, g.as].filter(Boolean).map(escapeHtml).join(' · ') || '—', { cls: 'span-2' })}
    </dl>`
  );

  const geoCard = card(
    'Geolocation',
    `<dl class="grid grid-2">
      ${field('Continent', g.continent ? `${escapeHtml(g.continent)} (${escapeHtml(g.continentCode || '—')})` : '—')}
      ${field('Country', g.country ? `${escapeHtml(g.country)} (${escapeHtml(g.countryCode || '—')})` : '—')}
      ${field('Region', g.regionName ? `${escapeHtml(g.regionName)} (${escapeHtml(g.region || '—')})` : '—')}
      ${field('City', E(g.city))}
      ${field('District', E(g.district))}
      ${field('Postal code', E(g.zip), { mono: true })}
      ${field('Latitude', g.latitude != null ? E(g.latitude) : '—', { mono: true })}
      ${field('Longitude', g.longitude != null ? E(g.longitude) : '—', { mono: true })}
      ${field('Timezone', E(g.timezone))}
      ${field('UTC offset', g.offset != null ? `UTC${g.offset >= 0 ? '+' : ''}${g.offset / 3600}` : '—', { mono: true })}
      ${field('Currency', E(g.currency), { cls: 'span-2' })}
    </dl>
    ${mapBlock}`
  );

  const flags = [];
  if (g.proxy === true) flags.push('<span class="badge badge-outline">Proxy</span>');
  if (g.hosting === true) flags.push('<span class="badge badge-outline">Hosting</span>');
  if (g.mobile === true) flags.push('<span class="badge badge-outline">Mobile</span>');
  if (flags.length === 0) flags.push('<span class="badge">Residential</span>');

  const networkCard = card(
    'Network',
    `<dl class="grid grid-2">
      ${field('ISP', E(g.isp))}
      ${field('Organization', E(g.org))}
      ${field('AS number', E(g.as), { mono: true })}
      ${field('AS name', E(g.asname))}
      ${field('Reverse DNS', E(g.reverse), { mono: true, cls: 'span-2' })}
      ${field('Reported query IP', E(g.query), { mono: true })}
    </dl>
    <div class="flags">${flags.join('')}</div>`
  );

  const deviceCard = card(
    'Device',
    `<dl class="grid grid-2">
      ${field('Browser', `${E(ua.family)} ${E(ua.full)}`)}
      ${field('Operating system', E(ua.os))}
      ${field('Device type', E(ua.device))}
      ${field('Preferred language', E(data.client.preferredLanguage))}
      ${field('All languages', data.client.languages.length ? data.client.languages.map(escapeHtml).join(', ') : '—', { cls: 'span-2' })}
      ${field('Referrer', E(data.client.referrer))}
      ${field('User-Agent', E(ua.raw), { mono: true, cls: 'span-2' })}
    </dl>`
  );

  const requestCard = card(
    'Request',
    `<dl class="grid grid-2">
      ${field('Method', E(data.request.method), { mono: true })}
      ${field('Protocol', E(data.request.protocol))}
      ${field('Hostname', E(data.request.hostname))}
      ${field('Client IP', E(data.ipAddress), { mono: true })}
      ${field('URL', E(data.request.originalUrl), { mono: true, cls: 'span-2' })}
      ${field('Requested at', E(data.requestedAt), { mono: true, cls: 'span-2' })}
    </dl>`
  );

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark">
<title>Client Info</title>
<style>
  :root {
    --background: oklch(0.145 0 0);
    --foreground: oklch(0.985 0 0);
    --card: oklch(0.205 0 0);
    --card-foreground: oklch(0.985 0 0);
    --primary: oklch(0.985 0 0);
    --primary-foreground: oklch(0.205 0 0);
    --secondary: oklch(0.269 0 0);
    --secondary-foreground: oklch(0.985 0 0);
    --muted: oklch(0.269 0 0);
    --muted-foreground: oklch(0.708 0 0);
    --accent: oklch(0.269 0 0);
    --accent-foreground: oklch(0.985 0 0);
    --border: oklch(0.269 0 0);
    --radius: 0.625rem;
    --font-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
      "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
      "Liberation Mono", "Courier New", monospace;
  }

  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  html { -webkit-text-size-adjust: 100%; }

  body {
    font-family: var(--font-sans);
    font-size: 0.875rem;
    line-height: 1.5;
    background: var(--background);
    color: var(--foreground);
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  .wrap {
    width: 100%;
    max-width: 960px;
    margin: 0 auto;
    padding: 1.5rem 1rem 3rem;
  }
  @media (min-width: 640px) {
    .wrap { padding: 2rem 1.5rem 4rem; }
  }
  @media (min-width: 1024px) {
    .wrap { padding: 2.5rem 2rem 5rem; }
  }

  .page-header {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  @media (min-width: 640px) {
    .page-header {
      flex-direction: row;
      align-items: center;
      justify-content: space-between;
    }
  }
  .page-header h1 {
    font-size: 1.125rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    margin: 0;
  }
  .page-header p {
    margin: 0.25rem 0 0;
    font-size: 0.8125rem;
    color: var(--muted-foreground);
    word-break: break-word;
  }
  .header-actions {
    display: flex;
    gap: 0.5rem;
    width: 100%;
  }
  @media (min-width: 640px) {
    .header-actions { width: auto; }
  }

  .btn {
    flex: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.375rem;
    height: 2.25rem;
    padding: 0 1rem;
    border-radius: calc(var(--radius) - 2px);
    font-size: 0.875rem;
    font-weight: 500;
    font-family: inherit;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--foreground);
    text-decoration: none;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    white-space: nowrap;
    -webkit-tap-highlight-color: transparent;
  }
  .btn:hover { background: var(--accent); color: var(--accent-foreground); }
  .btn-primary {
    background: var(--primary);
    color: var(--primary-foreground);
    border-color: var(--primary);
  }
  .btn-primary:hover { opacity: 0.9; background: var(--primary); color: var(--primary-foreground); }
  @media (min-width: 640px) {
    .btn { flex: 0 0 auto; }
  }

  .card {
    background: var(--card);
    color: var(--card-foreground);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 1rem;
  }
  .card-header {
    padding: 1rem 1rem 0.5rem;
  }
  @media (min-width: 640px) {
    .card-header { padding: 1rem 1.25rem 0.5rem; }
  }
  .card-title {
    font-size: 0.875rem;
    font-weight: 600;
    letter-spacing: -0.005em;
    margin: 0;
    color: var(--card-foreground);
  }
  .card-content {
    padding: 0.75rem 1rem 1rem;
  }
  @media (min-width: 640px) {
    .card-content { padding: 0.75rem 1.25rem 1.25rem; }
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.875rem 1.25rem;
    margin: 0;
  }
  @media (min-width: 640px) {
    .grid-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .span-2 { grid-column: span 2; }
  }

  .field { min-width: 0; margin: 0; }
  .field-label {
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--muted-foreground);
    margin: 0 0 0.25rem;
    line-height: 1.4;
  }
  .field-value {
    font-size: 0.875rem;
    color: var(--foreground);
    margin: 0;
    line-height: 1.5;
    word-break: break-word;
    overflow-wrap: anywhere;
  }
  .field-value.mono {
    font-family: var(--font-mono);
    font-size: 0.8125rem;
    color: var(--foreground);
  }

  .badge {
    display: inline-flex;
    align-items: center;
    border-radius: calc(var(--radius) - 4px);
    border: 1px solid transparent;
    background: var(--secondary);
    color: var(--secondary-foreground);
    font-size: 0.75rem;
    font-weight: 500;
    line-height: 1;
    padding: 0.25rem 0.5rem;
    white-space: nowrap;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .badge-outline {
    background: transparent;
    color: var(--foreground);
    border-color: var(--border);
  }

  .flags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.375rem;
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
  }

  .map-wrap {
    position: relative;
    width: 100%;
    margin-top: 1rem;
    border: 1px solid var(--border);
    border-radius: calc(var(--radius) - 2px);
    overflow: hidden;
    background: var(--muted);
    aspect-ratio: 16 / 10;
  }
  .map-wrap iframe {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
  }
  .map-empty {
    margin-top: 1rem;
    padding: 1.5rem 1rem;
    text-align: center;
    font-size: 0.8125rem;
    color: var(--muted-foreground);
    border: 1px dashed var(--border);
    border-radius: calc(var(--radius) - 2px);
  }
  @media (min-width: 640px) {
    .map-empty { padding: 2rem 1rem; }
  }

  .footer {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-top: 1.5rem;
    font-size: 0.75rem;
    color: var(--muted-foreground);
    word-break: break-word;
  }
  @media (min-width: 640px) {
    .footer {
      flex-direction: row;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
    }
  }
  .footer a {
    color: var(--muted-foreground);
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .footer a:hover { color: var(--foreground); }

  @media (prefers-reduced-motion: reduce) {
    .btn { transition: none; }
  }
</style>
</head>
<body>
<div class="wrap">

  <header class="page-header">
    <div>
      <h1>Client Info</h1>
      <p>Request, device, and network diagnostic · ${escapeHtml(data.requestedAt)}</p>
    </div>
    <div class="header-actions">
      <a class="btn btn-primary" href="?format=json">View JSON</a>
      <a class="btn" href="/">Refresh</a>
    </div>
  </header>

  ${summaryCard}
  ${geoCard}
  ${networkCard}
  ${deviceCard}
  ${requestCard}

  <footer class="footer">
    <span>ip-api.com · cached ${Math.round(GEO_CACHE_TTL_MS / 60000)} min</span>
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
