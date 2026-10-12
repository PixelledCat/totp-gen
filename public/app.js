const CONFIG = {
  period: 60,
  digits: 6,
  algorithm: 'SHA-1',
};

const MIN_SECRET_LENGTH = 8;
const EXPIRING_MS = 5000;
const RETRY_MS = 4000;
const COPY_FEEDBACK_MS = 1200;
const RECIPIENT_STORAGE_KEY = 'totpgen.recipient.v1';
const MANAGE_STORAGE_KEY = 'totpgen.manage.v1';
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function normalizeSecret(raw) {
  return raw.replace(/[\s-]/g, '').toUpperCase().replace(/=+$/, '');
}

function charsetError(value) {
  if (!/^[A-Z2-7]+$/.test(value)) {
    return 'Invalid secret. Base32 characters only (A\u2013Z and 2\u20137).';
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
  return new Uint8Array(bytes);
}

function counterToBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = counter;
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = value & 0xff;
    value = Math.floor(value / 256);
  }
  return bytes;
}

async function hmac(algorithm, key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(signature);
}

function truncate(hash, digits) {
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  const code = binary % 10 ** digits;
  return String(code).padStart(digits, '0');
}

async function generateTOTP(key, counter) {
  const hash = await hmac(CONFIG.algorithm, key, counterToBytes(counter));
  return truncate(hash, CONFIG.digits);
}

const secretInput = document.getElementById('secret');
const fieldEl = document.getElementById('secret-field');
const statusEl = document.getElementById('status');
const outputEl = document.getElementById('output');
const otpEl = document.getElementById('otp');
const copyBtn = document.getElementById('copy');
const barEl = document.getElementById('bar');
const countdownEl = document.getElementById('countdown');
const shareEl = document.getElementById('share');
const shareCreateBtn = document.getElementById('share-create');
const shareStatusEl = document.getElementById('share-status');
const shareResultEl = document.getElementById('share-result');
const shareUrlRowEl = document.getElementById('share-url-row');
const shareUrlEl = document.getElementById('share-url');
const shareCopyBtn = document.getElementById('share-copy');
const shareMetaEl = document.getElementById('share-meta');
const revokeBtn = document.getElementById('revoke');

const API = new URL('api/', document.baseURI).pathname;

const state = {
  mode: null,
  key: null,
  period: CONFIG.period,
  timeOffsetMs: 0,
  lastCounter: null,
  lastSeconds: null,
  genToken: 0,
  rafId: null,
  retryTimer: null,
  session: null,
  shareToken: null,
  share: null,
};

const copyTimers = new WeakMap();

function nowMs() {
  return Date.now() + state.timeOffsetMs;
}

function setStatus(message, tone = 'danger') {
  if (message) {
    statusEl.textContent = message;
    statusEl.classList.toggle('is-muted', tone === 'muted');
    statusEl.hidden = false;
  } else {
    statusEl.textContent = '';
    statusEl.hidden = true;
  }
}

function setShareStatus(message) {
  if (message) {
    shareStatusEl.textContent = message;
    shareStatusEl.hidden = false;
  } else {
    shareStatusEl.textContent = '';
    shareStatusEl.hidden = true;
  }
}

function resetButton(button) {
  clearTimeout(copyTimers.get(button));
  button.textContent = 'Copy';
  delete button.dataset.copied;
}

function flashButton(button) {
  button.textContent = 'Copied';
  button.dataset.copied = 'true';
  clearTimeout(copyTimers.get(button));
  copyTimers.set(button, setTimeout(() => resetButton(button), COPY_FEEDBACK_MS));
}

function stopLoop() {
  if (state.rafId !== null) {
    cancelAnimationFrame(state.rafId);
    state.rafId = null;
  }
}

function startLoop() {
  if (state.rafId === null) state.rafId = requestAnimationFrame(tick);
}

function renderShare() {
  const hasSecret = state.mode === 'local' && Boolean(state.key);
  const share = state.share;
  const hasStatus = shareStatusEl.textContent !== '';

  shareEl.hidden = !(hasSecret || share || hasStatus);
  shareCreateBtn.hidden = !hasSecret;
  shareResultEl.hidden = !share;
  if (!share) return;

  if (share.url) {
    shareUrlRowEl.hidden = false;
    shareUrlEl.textContent = share.url;
    shareMetaEl.textContent = `Expires ${formatExpiry(share.expiresAt)}`;
  } else {
    shareUrlRowEl.hidden = true;
    shareMetaEl.textContent = `Link created earlier. Expires ${formatExpiry(share.expiresAt)}. The URL is shown only once.`;
  }
}

function clearOutput() {
  stopLoop();
  state.mode = null;
  state.key = null;
  state.lastCounter = null;
  state.lastSeconds = null;
  state.genToken += 1;
  outputEl.hidden = true;
  otpEl.textContent = '';
  barEl.style.transform = 'scaleX(1)';
  barEl.classList.remove('is-expiring');
  resetButton(copyBtn);
  renderShare();
}

async function refreshLocalOtp(counter) {
  const token = (state.genToken += 1);
  const code = await generateTOTP(state.key, counter);
  if (token !== state.genToken) return;
  otpEl.textContent = code;
}

function tick() {
  state.rafId = requestAnimationFrame(tick);
  if (!state.mode) return;

  const periodMs = state.period * 1000;
  const now = nowMs();
  const remainingMs = periodMs - (now % periodMs);
  const counter = Math.floor(now / periodMs);

  barEl.style.transform = `scaleX(${(remainingMs / periodMs).toFixed(4)})`;
  barEl.classList.toggle('is-expiring', remainingMs <= EXPIRING_MS);

  const seconds = Math.ceil(remainingMs / 1000);
  if (seconds !== state.lastSeconds) {
    state.lastSeconds = seconds;
    countdownEl.textContent = `${seconds}s`;
  }

  if (counter !== state.lastCounter) {
    state.lastCounter = counter;
    if (state.mode === 'local') refreshLocalOtp(counter);
    else refreshRemoteOtp();
  }
}

function startLocal(normalized) {
  state.key = base32Decode(normalized);
  state.mode = 'local';
  state.period = CONFIG.period;
  state.timeOffsetMs = 0;
  state.lastCounter = null;
  state.lastSeconds = null;
  state.genToken += 1;
  outputEl.hidden = false;
  resetButton(copyBtn);
  startLoop();
  renderShare();
}

function handleInput() {
  const normalized = normalizeSecret(secretInput.value);

  if (!normalized) {
    setStatus('');
    clearOutput();
    return;
  }

  const error = charsetError(normalized);
  if (error) {
    setStatus(error);
    clearOutput();
    return;
  }

  setStatus('');
  if (normalized.length < MIN_SECRET_LENGTH) {
    clearOutput();
    return;
  }

  startLocal(normalized);
}

function handleBlur() {
  const normalized = normalizeSecret(secretInput.value);
  if (!normalized || charsetError(normalized)) return;
  if (normalized.length < MIN_SECRET_LENGTH) {
    setStatus('Secret is too short.');
  }
}

async function copyText(text, button) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    flashButton(button);
  } catch {
    if (fallbackCopy(text)) flashButton(button);
    else setStatus('Copy failed. Select the text manually.');
  }
}

function fallbackCopy(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.top = '-1000px';
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  document.body.removeChild(area);
  return ok;
}

function copyOtp() {
  const code = otpEl.textContent.trim();
  if (!/^\d+$/.test(code)) return;
  copyText(code, copyBtn);
}

function apiFetch(path, { method = 'GET', body, token } = {}) {
  const headers = {};
  const init = { method, headers };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  return fetch(API + path, init);
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

function relativeTime(targetMs) {
  const diff = targetMs - Date.now();
  if (diff <= 0) return 'expired';
  const totalMinutes = Math.floor(diff / 60000);
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return hours > 0 ? `in ${hours}h ${minutes}m` : `in ${minutes}m`;
}

function formatExpiry(ms) {
  const stamp = new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
  return `${stamp} UTC (${relativeTime(ms)})`;
}

function persistManage(share) {
  try {
    localStorage.setItem(MANAGE_STORAGE_KEY, JSON.stringify({
      id: share.id,
      revokeToken: share.revokeToken,
      expiresAt: share.expiresAt,
    }));
  } catch {}
}

function clearPersistedManage() {
  try {
    localStorage.removeItem(MANAGE_STORAGE_KEY);
  } catch {}
}

function restoreManage() {
  let raw;
  try {
    raw = localStorage.getItem(MANAGE_STORAGE_KEY);
  } catch {
    return;
  }
  if (!raw) return;

  let stored;
  try {
    stored = JSON.parse(raw);
  } catch {
    clearPersistedManage();
    return;
  }

  const valid = stored
    && typeof stored.id === 'string'
    && typeof stored.revokeToken === 'string'
    && typeof stored.expiresAt === 'number';

  if (!valid || Date.now() >= stored.expiresAt) {
    clearPersistedManage();
    return;
  }

  state.share = {
    url: null,
    id: stored.id,
    revokeToken: stored.revokeToken,
    expiresAt: stored.expiresAt,
  };
}

async function createShareLink() {
  const normalized = normalizeSecret(secretInput.value);
  const invalid = !normalized
    ? 'Enter a secret first.'
    : charsetError(normalized) || (normalized.length < MIN_SECRET_LENGTH ? 'Secret is too short.' : null);

  if (invalid) {
    setShareStatus(invalid);
    renderShare();
    return;
  }

  setShareStatus('');
  shareCreateBtn.disabled = true;
  try {
    const response = await apiFetch('links', {
      method: 'POST',
      body: {
        secret: normalized,
        period: CONFIG.period,
        digits: CONFIG.digits,
        algorithm: CONFIG.algorithm,
      },
    });
    const data = await readJson(response);
    if (!response.ok) {
      setShareStatus(data.error || 'Could not create a share link.');
      return;
    }
    state.share = {
      url: data.url,
      id: data.id,
      revokeToken: data.revokeToken,
      expiresAt: data.expiresAtMs,
    };
    persistManage(state.share);
  } catch {
    setShareStatus('Network error. Try again.');
  } finally {
    shareCreateBtn.disabled = false;
    renderShare();
  }
}

async function revokeShareLink() {
  const share = state.share;
  if (!share) return;

  revokeBtn.disabled = true;
  try {
    const response = await apiFetch(`links/${share.id}/revoke`, {
      method: 'POST',
      token: share.revokeToken,
    });
    if (response.ok) {
      state.share = null;
      clearPersistedManage();
      setShareStatus('Link revoked.');
    } else {
      const data = await readJson(response);
      setShareStatus(data.error || 'Could not revoke the link.');
    }
  } catch {
    setShareStatus('Network error. Try again.');
  } finally {
    revokeBtn.disabled = false;
    renderShare();
  }
}

function recipientToken() {
  const match = /[#&]t=([A-Za-z0-9_-]+)/.exec(location.hash);
  if (match) {
    try {
      sessionStorage.setItem(RECIPIENT_STORAGE_KEY, match[1]);
    } catch {}
    try {
      history.replaceState(null, '', location.pathname + location.search);
    } catch {}
    return match[1];
  }
  try {
    return sessionStorage.getItem(RECIPIENT_STORAGE_KEY);
  } catch {
    return null;
  }
}

function clearRecipient() {
  state.shareToken = null;
  state.session = null;
  try {
    sessionStorage.removeItem(RECIPIENT_STORAGE_KEY);
  } catch {}
}

function showUnavailable(reason) {
  clearRecipient();
  stopLoop();
  state.mode = null;
  outputEl.hidden = true;
  otpEl.textContent = '';
  setStatus(
    reason === 'revoked' ? 'This link has been revoked.'
      : reason === 'expired' ? 'This link has expired.'
        : 'This link is invalid.',
    'muted',
  );
}

function scheduleRetry() {
  clearTimeout(state.retryTimer);
  state.retryTimer = setTimeout(() => {
    state.retryTimer = null;
    if (state.mode === 'remote') refreshRemoteOtp();
  }, RETRY_MS);
}

function applyRemote(data) {
  state.timeOffsetMs = data.serverTime - Date.now();
  state.period = data.period;
  otpEl.textContent = data.code;
  state.lastCounter = Math.floor(data.windowEndsAt / (data.period * 1000)) - 1;
  state.lastSeconds = null;
}

async function renewSession() {
  if (!state.shareToken) {
    showUnavailable('not_found');
    return;
  }

  const token = (state.genToken += 1);
  try {
    const response = await apiFetch('session', {
      method: 'POST',
      body: { token: state.shareToken },
    });
    if (token !== state.genToken) return;

    const data = await readJson(response);
    if (response.status === 410 || response.status === 404) {
      showUnavailable(data.reason || 'not_found');
      return;
    }
    if (!response.ok) {
      scheduleRetry();
      return;
    }

    state.session = data.session;
    applyRemote(data);
  } catch {
    if (token === state.genToken) scheduleRetry();
  }
}

async function refreshRemoteOtp() {
  if (!state.session) {
    renewSession();
    return;
  }

  const token = (state.genToken += 1);
  try {
    const response = await apiFetch('code', { token: state.session });
    if (token !== state.genToken) return;

    if (response.status === 401) {
      renewSession();
      return;
    }

    const data = await readJson(response);
    if (response.status === 410 || response.status === 404) {
      showUnavailable(data.reason || 'not_found');
      return;
    }
    if (!response.ok) {
      scheduleRetry();
      return;
    }

    applyRemote(data);
  } catch {
    if (token === state.genToken) scheduleRetry();
  }
}

function initRecipient(token) {
  document.body.classList.add('is-recipient');
  fieldEl.hidden = true;
  state.mode = 'remote';
  state.shareToken = token;
  state.lastCounter = null;
  state.lastSeconds = null;
  state.genToken += 1;
  outputEl.hidden = false;
  otpEl.textContent = '\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7';
  startLoop();
  renewSession();
}

function initCreator() {
  restoreManage();
  secretInput.addEventListener('input', handleInput);
  secretInput.addEventListener('blur', handleBlur);
  shareCreateBtn.addEventListener('click', createShareLink);
  shareCopyBtn.addEventListener('click', () => copyText(state.share ? state.share.url : '', shareCopyBtn));
  revokeBtn.addEventListener('click', revokeShareLink);
  renderShare();
}

copyBtn.addEventListener('click', copyOtp);

const recipient = recipientToken();
if (recipient) {
  initRecipient(recipient);
} else if (!(window.crypto && window.crypto.subtle)) {
  secretInput.disabled = true;
  setStatus('This tool needs a secure context (HTTPS or localhost).');
} else {
  initCreator();
}

window.addEventListener('hashchange', () => {
  if (state.mode === 'remote') return;
  const token = recipientToken();
  if (token) initRecipient(token);
});
