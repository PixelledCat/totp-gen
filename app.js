const CONFIG = {
  period: 60,
  digits: 6,
  algorithm: 'SHA-1',
};

const MIN_SECRET_LENGTH = 8;
const EXPIRING_MS = 5000;
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
const statusEl = document.getElementById('status');
const outputEl = document.getElementById('output');
const otpEl = document.getElementById('otp');
const copyBtn = document.getElementById('copy');
const barEl = document.getElementById('bar');
const countdownEl = document.getElementById('countdown');

let activeKey = null;
let lastCounter = null;
let lastSeconds = null;
let genToken = 0;
let rafId = null;
let copyTimer = null;

function setStatus(message) {
  if (message) {
    statusEl.textContent = message;
    statusEl.hidden = false;
  } else {
    statusEl.textContent = '';
    statusEl.hidden = true;
  }
}

function resetCopy() {
  clearTimeout(copyTimer);
  copyTimer = null;
  copyBtn.textContent = 'Copy';
  delete copyBtn.dataset.copied;
}

function flashCopied() {
  copyBtn.textContent = 'Copied';
  copyBtn.dataset.copied = 'true';
  clearTimeout(copyTimer);
  copyTimer = setTimeout(resetCopy, 1200);
}

function stopLoop() {
  if (rafId !== null) {
    cancelAnimationFrame(rafId);
    rafId = null;
  }
}

function clearOutput() {
  stopLoop();
  activeKey = null;
  lastCounter = null;
  lastSeconds = null;
  genToken += 1;
  outputEl.hidden = true;
  otpEl.textContent = '';
  barEl.style.transform = 'scaleX(1)';
  barEl.classList.remove('is-expiring');
  resetCopy();
}

async function refreshOtp(counter) {
  const token = (genToken += 1);
  const code = await generateTOTP(activeKey, counter);
  if (token !== genToken) return;
  otpEl.textContent = code;
}

function tick() {
  rafId = requestAnimationFrame(tick);
  if (!activeKey) return;

  const periodMs = CONFIG.period * 1000;
  const now = Date.now();
  const remainingMs = periodMs - (now % periodMs);
  const counter = Math.floor(now / periodMs);

  barEl.style.transform = `scaleX(${(remainingMs / periodMs).toFixed(4)})`;
  barEl.classList.toggle('is-expiring', remainingMs <= EXPIRING_MS);

  const seconds = Math.ceil(remainingMs / 1000);
  if (seconds !== lastSeconds) {
    lastSeconds = seconds;
    countdownEl.textContent = `${seconds}s`;
  }

  if (counter !== lastCounter) {
    lastCounter = counter;
    refreshOtp(counter);
  }
}

function startSession(normalized) {
  activeKey = base32Decode(normalized);
  lastCounter = null;
  lastSeconds = null;
  genToken += 1;
  outputEl.hidden = false;
  resetCopy();
  if (rafId === null) rafId = requestAnimationFrame(tick);
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

  startSession(normalized);
}

function handleBlur() {
  const normalized = normalizeSecret(secretInput.value);
  if (!normalized || charsetError(normalized)) return;
  if (normalized.length < MIN_SECRET_LENGTH) {
    setStatus('Secret is too short.');
  }
}

async function copyCode() {
  const code = otpEl.textContent.trim();
  if (!/^\d+$/.test(code)) return;
  try {
    await navigator.clipboard.writeText(code);
    flashCopied();
  } catch {
    fallbackCopy(code);
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
  try {
    document.execCommand('copy');
    flashCopied();
  } catch {
    setStatus('Copy failed. Select the code manually.');
  }
  document.body.removeChild(area);
}

if (!(window.crypto && window.crypto.subtle)) {
  secretInput.disabled = true;
  setStatus('This tool needs a secure context (HTTPS or localhost).');
} else {
  secretInput.addEventListener('input', handleInput);
  secretInput.addEventListener('blur', handleBlur);
  copyBtn.addEventListener('click', copyCode);
}
