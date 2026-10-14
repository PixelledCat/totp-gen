'use strict';

const crypto = require('node:crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_RE = /^[A-Z2-7]+$/;
const MIN_SECRET_LENGTH = 8;

const HMAC_ALGORITHMS = {
  'SHA-1': 'sha1',
  'SHA-256': 'sha256',
  'SHA-512': 'sha512',
};

const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;
const DEFAULT_ALGORITHM = 'SHA-1';
const MIN_PERIOD = 15;
const MAX_PERIOD = 300;
const ALLOWED_DIGITS = [6, 8];

function normalizeSecret(raw) {
  if (typeof raw !== 'string') return '';
  return raw.replace(/[\s-]/g, '').toUpperCase().replace(/=+$/, '');
}

function secretError(normalized) {
  if (!normalized) return 'Secret is required.';
  if (!BASE32_RE.test(normalized)) {
    return 'Invalid secret. Base32 characters only (A\u2013Z and 2\u20137).';
  }
  if (normalized.length < MIN_SECRET_LENGTH) {
    return 'Secret is too short.';
  }
  return null;
}

function base32Decode(value) {
  let bits = 0;
  let buffer = 0;
  const bytes = [];
  for (const char of value) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Invalid Base32 character');
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return Buffer.from(bytes);
}

function counterToBytes(counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  return buf;
}

function hotp(key, counter, digits, algorithm) {
  const hmacName = HMAC_ALGORITHMS[algorithm];
  if (!hmacName) throw new Error('Unsupported algorithm');
  const digest = crypto.createHmac(hmacName, key).update(counterToBytes(counter)).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

function generateTotp(key, params, nowMs) {
  const periodMs = params.period * 1000;
  const counter = Math.floor(nowMs / periodMs);
  return {
    code: hotp(key, counter, params.digits, params.algorithm),
    windowEndsAt: (counter + 1) * periodMs,
  };
}

function parseParams(body) {
  const params = {
    period: DEFAULT_PERIOD,
    digits: DEFAULT_DIGITS,
    algorithm: DEFAULT_ALGORITHM,
  };

  if (body.period !== undefined) {
    if (!Number.isInteger(body.period) || body.period < MIN_PERIOD || body.period > MAX_PERIOD) {
      return { error: `Period must be an integer between ${MIN_PERIOD} and ${MAX_PERIOD}.` };
    }
    params.period = body.period;
  }

  if (body.digits !== undefined) {
    if (!ALLOWED_DIGITS.includes(body.digits)) {
      return { error: `Digits must be one of ${ALLOWED_DIGITS.join(', ')}.` };
    }
    params.digits = body.digits;
  }

  if (body.algorithm !== undefined) {
    if (!Object.hasOwn(HMAC_ALGORITHMS, body.algorithm)) {
      return { error: `Algorithm must be one of ${Object.keys(HMAC_ALGORITHMS).join(', ')}.` };
    }
    params.algorithm = body.algorithm;
  }

  return { params };
}

module.exports = {
  BASE32_RE,
  DEFAULT_ALGORITHM,
  DEFAULT_DIGITS,
  DEFAULT_PERIOD,
  HMAC_ALGORITHMS,
  MIN_SECRET_LENGTH,
  base32Decode,
  generateTotp,
  normalizeSecret,
  parseParams,
  secretError,
};
