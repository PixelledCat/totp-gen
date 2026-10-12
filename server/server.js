'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const { createStore } = require('./store');
const { base32Decode, generateTotp, normalizeSecret, parseParams, secretError } = require('./totp');

const MAX_BODY_BYTES = 4 * 1024;
const SESSION_TOKEN_TTL_CAP_MS = 30 * 60 * 1000;
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;

const CREATE_ALLOWED_KEYS = new Set(['secret', 'period', 'digits', 'algorithm']);
const SESSION_ALLOWED_KEYS = new Set(['token']);

const RATE_LIMITS = {
  create: { max: 10, windowMs: 60 * 60 * 1000 },
  session: { max: 30, windowMs: 5 * 60 * 1000 },
  code: { max: 120, windowMs: 60 * 1000 },
  revoke: { max: 10, windowMs: 60 * 60 * 1000 },
};

const REVOKE_PATH_RE = /^\/links\/([0-9a-f]{16})\/revoke$/;

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function loadConfig(env) {
  const encKey = Buffer.from(env.TOTP_ENC_KEY ?? '', 'base64');
  if (encKey.length !== 32) {
    throw new Error('TOTP_ENC_KEY must be exactly 32 bytes of base64');
  }
  const sessionSecret = Buffer.from(env.SESSION_SECRET ?? '', 'base64');
  if (sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 bytes of base64');
  }

  return {
    host: env.HOST ?? '127.0.0.1',
    port: positiveInt(env.PORT, 8110),
    encKey,
    sessionSecret,
    dataFile: env.DATA_FILE ?? '/var/lib/totp-gen/links.json',
    baseUrl: (env.BASE_URL ?? 'https://ezlife.space/totp-gen').replace(/\/+$/, ''),
    linkTtlMs: positiveInt(env.LINK_TTL_MS, 48 * 60 * 60 * 1000),
    retentionMs: positiveInt(env.RETENTION_DAYS, 7) * 24 * 60 * 60 * 1000,
    sessionTtlMs: positiveInt(env.SESSION_TTL_MS, SESSION_TOKEN_TTL_CAP_MS),
    maxLinks: positiveInt(env.MAX_LINKS, 5000),
  };
}

function redact(value) {
  return String(value).replace(/[A-Za-z0-9_-]{32,}/g, '[redacted]');
}

function log(message) {
  process.stdout.write(`${new Date().toISOString()} ${redact(message)}\n`);
}

function warn(message) {
  process.stderr.write(`${new Date().toISOString()} WARN ${redact(message)}\n`);
}

function ensureKnownKeys(body, allowed) {
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) return `Unexpected field: ${key}`;
  }
  return null;
}

function signSession(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifySession(token, secret) {
  if (typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;

  const body = token.slice(0, dot);
  const expected = crypto.createHmac('sha256', secret).update(body).digest();
  let provided;
  try {
    provided = Buffer.from(token.slice(dot + 1), 'base64url');
  } catch {
    return null;
  }
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (typeof payload.linkId !== 'string' || typeof payload.exp !== 'number') return null;
    return payload;
  } catch {
    return null;
  }
}

function createRateLimiter() {
  const buckets = new Map();

  return {
    hit(key, limit, now) {
      let bucket = buckets.get(key);
      if (!bucket || now >= bucket.resetAt) {
        bucket = { count: 0, resetAt: now + limit.windowMs };
        buckets.set(key, bucket);
      }
      bucket.count += 1;
      if (bucket.count > limit.max) {
        return { ok: false, retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)) };
      }
      return { ok: true };
    },
    prune(now) {
      for (const [key, bucket] of buckets) {
        if (now >= bucket.resetAt) buckets.delete(key);
      }
    },
  };
}

function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    ...extraHeaders,
  });
  res.end(body);
  return status;
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const err = new Error('Payload too large');
      err.status = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  if (size === 0) return {};

  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const err = new Error('Invalid JSON body');
    err.status = 400;
    throw err;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    const err = new Error('Invalid JSON body');
    err.status = 400;
    throw err;
  }
  return parsed;
}

function bearerToken(req) {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer (.+)$/.exec(header);
  return match ? match[1] : null;
}

function clientIp(req) {
  return req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';
}

function unavailableReason(record, now) {
  if (record.revokedAt !== null) return 'revoked';
  if (now >= record.expiresAt) return 'expired';
  return null;
}

function createServer({ config, store, now = Date.now }) {
  const limiter = createRateLimiter();

  function limit(req, name) {
    const state = limiter.hit(`${name}:${clientIp(req)}`, RATE_LIMITS[name], now());
    return state;
  }

  async function handleCreate(req, res) {
    const state = limit(req, 'create');
    if (!state.ok) return sendJson(res, 429, { error: 'Too many links created. Try again later.' }, { 'Retry-After': String(state.retryAfter) });

    const body = await readJsonBody(req);
    const unknown = ensureKnownKeys(body, CREATE_ALLOWED_KEYS);
    if (unknown) return sendJson(res, 400, { error: unknown });

    const normalized = normalizeSecret(body.secret);
    const invalid = secretError(normalized);
    if (invalid) return sendJson(res, 400, { error: invalid });

    const parsed = parseParams(body);
    if (parsed.error) return sendJson(res, 400, { error: parsed.error });

    const at = now();
    if (store.activeCount(at) >= config.maxLinks) {
      return sendJson(res, 503, { error: 'Link capacity reached. Try again later.' });
    }

    const { record, token, revokeToken } = await store.createLink({
      secretBytes: base32Decode(normalized),
      params: parsed.params,
      now: at,
    });

    return sendJson(res, 201, {
      id: record.id,
      url: `${config.baseUrl}/#t=${token}`,
      expiresAt: new Date(record.expiresAt).toISOString(),
      expiresAtMs: record.expiresAt,
      revokeToken,
    });
  }

  async function handleSession(req, res) {
    const state = limit(req, 'session');
    if (!state.ok) return sendJson(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(state.retryAfter) });

    const body = await readJsonBody(req);
    const unknown = ensureKnownKeys(body, SESSION_ALLOWED_KEYS);
    if (unknown) return sendJson(res, 400, { error: unknown });

    if (typeof body.token !== 'string' || body.token.length === 0) {
      return sendJson(res, 400, { error: 'Token is required.' });
    }

    const record = store.findByToken(body.token);
    if (!record) return sendJson(res, 404, { error: 'This link is invalid.', reason: 'not_found' });

    const at = now();
    const reason = unavailableReason(record, at);
    if (reason) {
      const message = reason === 'revoked' ? 'This link has been revoked.' : 'This link has expired.';
      return sendJson(res, 410, { error: message, reason });
    }

    const exp = Math.min(at + config.sessionTtlMs, record.expiresAt);
    const session = signSession({ linkId: record.id, exp }, config.sessionSecret);
    const { code, windowEndsAt } = generateTotp(store.decryptSecret(record.cipher), record, at);

    return sendJson(res, 200, {
      session,
      period: record.period,
      digits: record.digits,
      code,
      serverTime: at,
      windowEndsAt,
      linkExpiresAt: record.expiresAt,
    });
  }

  async function handleCode(req, res) {
    const state = limit(req, 'code');
    if (!state.ok) return sendJson(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(state.retryAfter) });

    const payload = verifySession(bearerToken(req), config.sessionSecret);
    if (!payload) return sendJson(res, 401, { error: 'Session is invalid or has expired.' });

    const at = now();
    if (at >= payload.exp) return sendJson(res, 401, { error: 'Session is invalid or has expired.' });

    const record = store.findById(payload.linkId);
    if (!record) return sendJson(res, 401, { error: 'Session is invalid or has expired.' });

    const reason = unavailableReason(record, at);
    if (reason) {
      const message = reason === 'revoked' ? 'This link has been revoked.' : 'This link has expired.';
      return sendJson(res, 410, { error: message, reason });
    }

    const { code, windowEndsAt } = generateTotp(store.decryptSecret(record.cipher), record, at);

    return sendJson(res, 200, {
      code,
      period: record.period,
      digits: record.digits,
      serverTime: at,
      windowEndsAt,
      linkExpiresAt: record.expiresAt,
    });
  }

  async function handleRevoke(req, res, id) {
    const state = limit(req, 'revoke');
    if (!state.ok) return sendJson(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(state.retryAfter) });

    const token = bearerToken(req);
    if (!token) return sendJson(res, 401, { error: 'Missing revoke token.' });

    const result = await store.revoke(id, token, now());
    if (!result.ok) {
      if (result.reason === 'not_found') return sendJson(res, 404, { error: 'This link is invalid.', reason: 'not_found' });
      return sendJson(res, 403, { error: 'Revoke token does not match.' });
    }
    return sendJson(res, 200, { revoked: true });
  }

  const server = http.createServer(async (req, res) => {
    const started = now();
    const path = (req.url ?? '/').split('?')[0];
    let status = 500;

    try {
      const revokeMatch = REVOKE_PATH_RE.exec(path);
      if (req.method === 'POST' && path === '/links') {
        status = await handleCreate(req, res);
      } else if (req.method === 'POST' && path === '/session') {
        status = await handleSession(req, res);
      } else if (req.method === 'GET' && path === '/code') {
        status = await handleCode(req, res);
      } else if (req.method === 'POST' && revokeMatch) {
        status = await handleRevoke(req, res, revokeMatch[1]);
      } else if (req.method === 'GET' && path === '/healthz') {
        sendJson(res, 200, { ok: true });
        status = 200;
      } else {
        sendJson(res, 404, { error: 'Not found.' });
        status = 404;
      }
    } catch (err) {
      status = err.status ?? 500;
      if (status >= 500) warn(`request failed: ${err.name}: ${err.message}`);
      if (!res.headersSent) {
        sendJson(res, status, { error: status >= 500 ? 'Internal error.' : err.message });
      }
    } finally {
      log(`${req.method} ${path} ${status} ${now() - started}ms ip=${clientIp(req)}`);
    }
  });

  server.keepAliveTimeout = 5000;
  server.headersTimeout = 10000;

  return { server, limiter };
}

async function main() {
  const config = loadConfig(process.env);
  const store = createStore({
    dataFile: config.dataFile,
    encryptionKey: config.encKey,
    linkTtlMs: config.linkTtlMs,
    logger: { warn },
  });
  await store.load();

  const removed = await store.sweep(Date.now(), config.retentionMs);
  const sweepTimer = setInterval(() => {
    store.sweep(Date.now(), config.retentionMs).catch((err) => warn(`sweep failed: ${err.message}`));
  }, SWEEP_INTERVAL_MS);
  sweepTimer.unref();

  const { server, limiter } = createServer({ config, store });

  const pruneTimer = setInterval(() => limiter.prune(Date.now()), 10 * 60 * 1000);
  pruneTimer.unref();

  server.listen(config.port, config.host, () => {
    log(`listening on ${config.host}:${config.port}; links=${store.totalCount()} purgedOnBoot=${removed}`);
  });

  const shutdown = (signal) => {
    log(`received ${signal}, shutting down`);
    clearInterval(sweepTimer);
    clearInterval(pruneTimer);
    server.close(() => {
      store.persist().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    warn(`uncaught exception: ${err.name}: ${err.message}`);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    warn(`unhandled rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
  });
}

if (require.main === module) {
  main().catch((err) => {
    warn(`startup failed: ${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  clientIp,
  createServer,
  loadConfig,
  redact,
  signSession,
  verifySession,
};
