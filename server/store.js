'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const LINK_TTL_MS = 48 * 60 * 60 * 1000;

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function hashesEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function createStore({ dataFile, encryptionKey, linkTtlMs = LINK_TTL_MS, logger }) {
  const key = encryptionKey;
  let links = [];
  let byTokenHash = new Map();
  let byId = new Map();
  let writeChain = Promise.resolve();

  function encryptSecret(secretBytes) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(secretBytes), cipher.final()]);
    return {
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ct: ct.toString('base64'),
    };
  }

  function decryptSecret(cipherObj) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(cipherObj.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(cipherObj.tag, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(cipherObj.ct, 'base64')),
      decipher.final(),
    ]);
  }

  function reindex() {
    byTokenHash = new Map();
    byId = new Map();
    for (const record of links) {
      byTokenHash.set(record.tokenHash, record);
      byId.set(record.id, record);
    }
  }

  async function writeSnapshot() {
    const tmp = `${dataFile}.tmp`;
    const handle = await fs.open(tmp, 'w', 0o600);
    try {
      await handle.writeFile(JSON.stringify({ links }), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(tmp, dataFile);
  }

  function persist() {
    writeChain = writeChain.then(writeSnapshot, writeSnapshot);
    return writeChain;
  }

  async function load() {
    await fs.mkdir(path.dirname(dataFile), { recursive: true });
    let raw;
    try {
      raw = await fs.readFile(dataFile, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        links = [];
        reindex();
        return;
      }
      throw err;
    }

    try {
      const parsed = JSON.parse(raw);
      links = Array.isArray(parsed.links) ? parsed.links : [];
    } catch {
      const quarantine = `${dataFile}.corrupt-${Date.now()}`;
      await fs.rename(dataFile, quarantine);
      logger?.warn(`data file unreadable, quarantined to ${quarantine}`);
      links = [];
    }
    reindex();
  }

  function isActive(record, now) {
    return record.revokedAt === null && now < record.expiresAt;
  }

  function findByToken(token) {
    if (typeof token !== 'string' || token.length === 0) return null;
    return byTokenHash.get(sha256Hex(token)) ?? null;
  }

  function findById(id) {
    if (typeof id !== 'string') return null;
    return byId.get(id) ?? null;
  }

  async function createLink({ secretBytes, params, now }) {
    const token = crypto.randomBytes(32).toString('base64url');
    const revokeToken = crypto.randomBytes(32).toString('base64url');
    const record = {
      id: crypto.randomBytes(8).toString('hex'),
      tokenHash: sha256Hex(token),
      revokeHash: sha256Hex(revokeToken),
      cipher: encryptSecret(secretBytes),
      period: params.period,
      digits: params.digits,
      algorithm: params.algorithm,
      createdAt: now,
      expiresAt: now + linkTtlMs,
      revokedAt: null,
    };
    links.push(record);
    byTokenHash.set(record.tokenHash, record);
    byId.set(record.id, record);
    await persist();
    return { record, token, revokeToken };
  }

  async function revoke(id, revokeToken, now) {
    const record = findById(id);
    if (!record) return { ok: false, reason: 'not_found' };
    if (!hashesEqual(record.revokeHash, sha256Hex(revokeToken))) {
      return { ok: false, reason: 'forbidden' };
    }
    if (record.revokedAt === null) {
      record.revokedAt = now;
      await persist();
    }
    return { ok: true, record };
  }

  async function sweep(now, retentionMs, { force = false } = {}) {
    const cutoff = now - retentionMs;
    const kept = links.filter((record) => {
      const endedAt = record.revokedAt ?? record.expiresAt;
      return endedAt >= cutoff;
    });
    const removed = links.length - kept.length;
    if (removed > 0 || force) {
      links = kept;
      reindex();
      await persist();
    }
    return removed;
  }

  function activeCount(now) {
    let count = 0;
    for (const record of links) if (isActive(record, now)) count += 1;
    return count;
  }

  return {
    activeCount,
    createLink,
    decryptSecret,
    findByToken,
    findById,
    isActive,
    load,
    persist,
    revoke,
    sweep,
    totalCount: () => links.length,
  };
}

module.exports = { LINK_TTL_MS, createStore, hashesEqual, sha256Hex };
