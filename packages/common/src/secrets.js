import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { encrypt, decrypt } from './crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Resolved from this file, not cwd: every service must read the same files.
const SECRETS_DIR = path.resolve(__dirname, '../../../data/.secrets');

const cache = new Map();

/**
 * Resolves a service secret: explicit env var first, else a random value
 * generated once and persisted under data/.secrets/ (shared by all local services).
 * @param {string} name file-safe secret name
 * @param {string} [envVar] env var that overrides the file
 * @returns {string}
 */
export function resolveSecret(name, envVar) {
  const fromEnv = envVar ? (process.env[envVar] || '').trim() : '';
  if (fromEnv) return fromEnv;
  if (cache.has(name)) return cache.get(name);

  const file = path.join(SECRETS_DIR, name);
  let value = '';
  try { value = fs.readFileSync(file, 'utf8').trim(); } catch {}
  if (!value) {
    fs.mkdirSync(SECRETS_DIR, { recursive: true });
    const fresh = crypto.randomBytes(32).toString('hex');
    try {
      fs.writeFileSync(file, fresh, { flag: 'wx', mode: 0o600 });
      value = fresh;
    } catch {
      // Another process created it first: use theirs.
      value = fs.readFileSync(file, 'utf8').trim();
    }
  }
  cache.set(name, value);
  return value;
}

/** Constant-time string comparison (length-independent via hashing). */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

export const getAdminToken = () => resolveSecret('admin_api_token', 'ADMIN_API_TOKEN');
export const getObserverToken = () => resolveSecret('observer_api_token', 'OBSERVER_API_TOKEN');
export const getCoinStoreWebhookSecret = () => resolveSecret('coin_store_webhook_secret', 'COIN_STORE_WEBHOOK_SECRET');

/**
 * Shared credential proving a request originated from a co-located service (server-side render
 * proxies) rather than a browser. A plain `X-Internal-Render: true` header is attacker-settable,
 * so the header is only honoured together with this secret.
 */
export const getInternalServiceToken = () => resolveSecret('internal_service_token', 'INTERNAL_SERVICE_TOKEN');

/** True only when the caller proves it is a trusted internal service. */
export function isInternalServiceRequest(req) {
  const match = /^Bearer\s+(.+)$/i.exec(req?.headers?.['authorization'] || '');
  const presented = (match ? match[1].trim() : '') || (req?.headers?.['x-internal-token'] || '');
  return Boolean(presented) && safeEqual(presented, getInternalServiceToken());
}

/** Literal that older builds seeded into databases; must never be trusted. */
export const LEGACY_DEFAULT_WEBHOOK_SECRET = 'merchant_webhook_secret_for_wallet_store';

/**
 * Master key for encrypting data at rest (merchant webhook secrets, OTPs).
 * Generated once and persisted alongside the other local secrets.
 */
export const getEncryptionMasterKey = () => resolveSecret('encryption_master_key', 'ENCRYPTION_MASTER_KEY');

/** Envelope prefix marking a stored value as AES-256-GCM ciphertext. */
const ENC_PREFIX = 'enc:v1:';

/** True when a stored value is in the ciphertext envelope. */
export function isEncryptedValue(value) {
  return typeof value === 'string' && value.startsWith(ENC_PREFIX);
}

/**
 * Encrypts a value for storage. Values are idempotent: an already-encrypted value is
 * returned unchanged so callers can wrap reads and writes without tracking state.
 */
export function encryptAtRest(plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === '') return plaintext;
  if (isEncryptedValue(plaintext)) return plaintext;
  return ENC_PREFIX + encrypt(String(plaintext), getEncryptionMasterKey());
}

/**
 * Decrypts a stored value, transparently passing through values written before encryption
 * existed (plaintext) so existing databases keep working and get re-encrypted on next write.
 */
export function decryptAtRest(stored) {
  if (!isEncryptedValue(stored)) return stored;
  try {
    return decrypt(stored.slice(ENC_PREFIX.length), getEncryptionMasterKey());
  } catch {
    // A value encrypted under a different/lost key must not silently become plaintext.
    return null;
  }
}

/**
 * Keyed digest for high-entropy secrets that are only ever looked up, never read back
 * (session tokens, device tokens). Unlike a plain hash this is not brute-forceable from a
 * database dump, because the key lives outside the database.
 */
export function blindIndex(value, namespace = 'token') {
  if (value === null || value === undefined || value === '') return null;
  const digest = crypto.createHmac('sha256', getInternalServiceToken())
    .update(`${namespace}:${value}`)
    .digest('hex');
  return `${namespace}_v1_${digest}`;
}

/**
 * Compares a presented secret against a stored blind index in constant time.
 */
export function blindIndexMatches(value, storedIndex, namespace = 'token') {
  const candidate = blindIndex(value, namespace);
  if (!candidate || !storedIndex) return false;
  return safeEqual(candidate, storedIndex);
}

/** True when the request's `Authorization: Bearer` value matches any of the given tokens. */
export function hasBearer(req, ...tokens) {
  const match = /^Bearer\s+(.+)$/i.exec(req?.headers?.['authorization'] || '');
  if (!match) return false;
  const presented = match[1].trim();
  return tokens.some(t => safeEqual(presented, t));
}

const BLOCKED_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback']);

/** True for loopback, RFC1918, link-local, CGNAT, multicast and reserved IPv4/IPv6 ranges. */
function isPrivateAddress(hostname) {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (lower === '::1' || lower === '::' || lower === '0.0.0.0') return true;
  if (lower.endsWith('.local') || lower.endsWith('.internal') || lower.endsWith('.localhost')) return true;

  const v4 = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!v4) {
    // Unique-local (fc00::/7) and link-local (fe80::/10) IPv6.
    return /^f[cd][0-9a-f]{2}:/.test(lower) || /^fe[89ab][0-9a-f]:/.test(lower);
  }
  const [a, b] = [Number(v4[1]), Number(v4[2])];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

/**
 * Self-hosted merchants legitimately deliver webhooks to a host on their own LAN or loopback,
 * so those are permitted only when explicitly opted in. Without the opt-in, private, loopback
 * and link-local targets (including the cloud metadata endpoint) are refused.
 */
function privateWebhooksAllowed() {
  return process.env.YOUPI_ALLOW_PRIVATE_WEBHOOKS === 'true';
}

/**
 * Validates an operator-supplied outbound webhook URL.
 * Rejects non-HTTP(S) schemes, embedded credentials and — unless explicitly opted in —
 * loopback/private/link-local hosts, so the gateway cannot be pointed at cloud metadata
 * endpoints or its own internal admin/control-plane services (SSRF).
 * @param {string} value
 * @returns {{ valid: boolean, error?: string, url?: URL }}
 */
export function validateOutboundWebhookUrl(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return { valid: false, error: 'Webhook URL is required.' };
  if (raw.length > 2048) return { valid: false, error: 'Webhook URL is too long.' };

  let url;
  try {
    url = new URL(raw);
  } catch {
    return { valid: false, error: 'Webhook URL must be a valid absolute URL.' };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { valid: false, error: 'Webhook URL must use http:// or https://' };
  }
  if (url.username || url.password) {
    return { valid: false, error: 'Webhook URL must not embed credentials.' };
  }
  const hostname = (url.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!hostname) return { valid: false, error: 'Webhook URL must include a hostname.' };
  if (!privateWebhooksAllowed() && (BLOCKED_HOSTNAMES.has(hostname) || isPrivateAddress(hostname))) {
    return {
      valid: false,
      error: 'Webhook URL must not point to a loopback or private network address (set YOUPI_ALLOW_PRIVATE_WEBHOOKS=true for self-hosted LAN targets).'
    };
  }
  return { valid: true, url };
}

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const consumedOAuthStates = new Map();

function oauthStateMac(payload) {
  return crypto.createHmac('sha256', getObserverToken()).update(`oauth-state:${payload}`).digest('hex');
}

/**
 * Creates a signed, expiring OAuth `state` value. Mint it only from an authenticated admin route:
 * the callback accepts nothing that was not minted there, which blocks login-CSRF account linking.
 */
export function createOAuthState() {
  const payload = `${crypto.randomBytes(16).toString('hex')}.${Date.now() + OAUTH_STATE_TTL_MS}`;
  return `${payload}.${oauthStateMac(payload)}`;
}

/** Verifies signature and expiry, and accepts each state only once (per process). */
export function consumeOAuthState(state) {
  if (typeof state !== 'string') return false;
  const parts = state.split('.');
  if (parts.length !== 3) return false;
  const [nonce, expiresAt, mac] = parts;
  if (!safeEqual(mac, oauthStateMac(`${nonce}.${expiresAt}`))) return false;
  const now = Date.now();
  if (!(Number(expiresAt) > now)) return false;
  for (const [key, exp] of consumedOAuthStates) if (exp <= now) consumedOAuthStates.delete(key);
  if (consumedOAuthStates.has(nonce)) return false;
  consumedOAuthStates.set(nonce, Number(expiresAt));
  return true;
}
