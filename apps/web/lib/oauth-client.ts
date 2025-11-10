/*
 * OAuth 2.0 Authorization Code + PKCE helper tailored for the Aunsorm Server.
 *
 * This module exposes deterministic utilities for generating PKCE verifiers,
 * computing their S256 code challenges and orchestrating the full
 * authorization-code exchange with CSRF (state) validation.  All random
 * sources, hashing primitives, storage adapters and fetch implementations can
 * be injected which keeps the helpers testable and framework agnostic.
 */

const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
const BASE64URL_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export type RandomSource = (length: number) => Promise<Uint8Array>;
export type DigestFn = (data: Uint8Array) => Promise<Uint8Array>;

export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface BeginAuthorizationParams {
  clientId: string;
  redirectUri: string;
  scope?: string;
  subject?: string;
  /**
   * Optional externally provided state.  When omitted a cryptographically
   * secure random value will be generated and persisted automatically.
   */
  state?: string;
}

export interface BeginAuthorizationResult {
  code: string;
  /** The state value stored locally (generated or provided by the caller). */
  state: string;
  expiresIn: number;
  /**
   * The PKCE code verifier that must be supplied when exchanging the
   * authorization code.  The value is kept in the configured storage adapter
   * and returned here for convenience (e.g. telemetry).
   */
  codeVerifier: string;
}

export interface ExchangeTokenParams {
  code: string;
  redirectUri: string;
  clientId: string;
}

export interface TokenResponseBody {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export interface OAuthClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  storage?: KeyValueStore;
  randomSource?: RandomSource;
  digestFn?: DigestFn;
  stateStorageKey?: string;
  verifierStorageKey?: string;
  tokenStorageKey?: string;
}

const DEFAULT_STATE_KEY = 'aunsorm.oauth.state';
const DEFAULT_VERIFIER_KEY = 'aunsorm.oauth.code_verifier';
const DEFAULT_TOKEN_KEY = 'aunsorm.oauth.access_token';

const DEFAULT_CODE_VERIFIER_LENGTH = 64;
const DEFAULT_STATE_LENGTH = 32;

const LOOPBACK_HOSTNAME_ALIASES = new Set([
  'localhost',
  'localhost.localdomain',
  'localhost6',
  'localhost6.localdomain6',
  'ip6-localhost',
  'ip6-loopback',
]);

function normaliseHostname(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function isLoopbackIpv4(candidate: string): boolean {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(candidate)) {
    return false;
  }

  const segments = candidate.split('.').map((segment) => Number.parseInt(segment, 10));
  if (segments.length !== 4 || segments.some((segment) => Number.isNaN(segment) || segment < 0 || segment > 255)) {
    return false;
  }

  if (segments[0] === 127) {
    return true;
  }

  return segments.every((segment) => segment === 0);
}

function decodeHexIpv4Mapped(mapped: string): string | undefined {
  const segments = mapped.split(':').filter((segment) => segment.length > 0);
  if (segments.length !== 2) {
    return undefined;
  }

  if (!segments.every((segment) => /^[0-9a-f]{1,4}$/i.test(segment))) {
    return undefined;
  }

  const [high, low] = segments;
  const highValue = Number.parseInt(high, 16);
  const lowValue = Number.parseInt(low, 16);
  if (Number.isNaN(highValue) || Number.isNaN(lowValue)) {
    return undefined;
  }

  const bytes = [
    (highValue >> 8) & 0xff,
    highValue & 0xff,
    (lowValue >> 8) & 0xff,
    lowValue & 0xff,
  ];

  return bytes.join('.');
}

function isLoopbackHostname(hostname: string): boolean {
  const normalised = normaliseHostname(hostname);
  if (!normalised) {
    return false;
  }

  if (LOOPBACK_HOSTNAME_ALIASES.has(normalised) || normalised.endsWith('.localhost')) {
    return true;
  }

  if (normalised === '::1' || normalised === '0:0:0:0:0:0:0:1') {
    return true;
  }

  if (normalised === '::' || normalised === '::0' || normalised === '0:0:0:0:0:0:0:0') {
    return true;
  }

  if (normalised.startsWith('::ffff:')) {
    const mapped = normalised.slice('::ffff:'.length);
    if (isLoopbackIpv4(mapped)) {
      return true;
    }
    const decoded = decodeHexIpv4Mapped(mapped);
    if (decoded && isLoopbackIpv4(decoded)) {
      return true;
    }
    return false;
  }

  return isLoopbackIpv4(normalised);
}

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

function base64UrlEncode(data: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(data)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  let binary = '';
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  const base64 = typeof btoa === 'function' ? btoa(binary) : binary;
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function defaultRandomSource(length: number): Promise<Uint8Array> {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return buffer;
  }
  const { randomBytes } = await import('node:crypto');
  return new Uint8Array(randomBytes(length));
}

async function defaultDigestFn(data: Uint8Array): Promise<Uint8Array> {
  if (
    typeof crypto !== 'undefined' &&
    typeof crypto.subtle !== 'undefined' &&
    typeof crypto.subtle.digest === 'function'
  ) {
    const digest = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(digest);
  }
  const { createHash } = await import('node:crypto');
  const hash = createHash('sha256');
  hash.update(data);
  return new Uint8Array(hash.digest());
}

async function randomString(
  length: number,
  charset: string,
  randomSource: RandomSource,
): Promise<string> {
  if (length <= 0) {
    throw new Error('Length must be greater than zero.');
  }
  const chars = Array.from(charset);
  const maxByte = 256 - (256 % chars.length);
  const result: string[] = [];

  while (result.length < length) {
    const batchSize = Math.ceil((length - result.length) * 1.25);
    const bytes = await randomSource(batchSize);

    for (const value of bytes) {
      if (value >= maxByte) {
        continue;
      }
      result.push(chars[value % chars.length]);
      if (result.length === length) {
        break;
      }
    }
  }

  return result.join('');
}

export async function generateCodeVerifier(
  length = DEFAULT_CODE_VERIFIER_LENGTH,
  randomSource: RandomSource = defaultRandomSource,
): Promise<string> {
  if (length < 43 || length > 128) {
    throw new Error('code_verifier length must be between 43 and 128 characters.');
  }
  return randomString(length, PKCE_CHARSET, randomSource);
}

export async function generateState(
  length = DEFAULT_STATE_LENGTH,
  randomSource: RandomSource = defaultRandomSource,
): Promise<string> {
  return randomString(length, BASE64URL_CHARSET, randomSource);
}

export async function computeCodeChallenge(
  codeVerifier: string,
  digestFn: DigestFn = defaultDigestFn,
): Promise<string> {
  if (!codeVerifier || codeVerifier.length < 43) {
    throw new Error('code_verifier must be a non-empty string (43+ characters).');
  }
  const encoder = new TextEncoder();
  const input = encoder.encode(codeVerifier);
  const digest = await digestFn(input);
  return base64UrlEncode(digest);
}

function ensureFetch(fetchImpl?: typeof fetch): typeof fetch {
  if (fetchImpl) {
    return fetchImpl;
  }
  if (typeof fetch === 'function') {
    return fetch;
  }
  throw new Error('No fetch implementation available.');
}

function detectStorage(storage?: KeyValueStore): KeyValueStore | undefined {
  if (storage) {
    return storage;
  }
  if (typeof sessionStorage !== 'undefined') {
    return sessionStorage;
  }
  return undefined;
}

function parseUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim();
  if (trimmed.length === 0) {
    throw new Error('baseUrl is required.');
  }
  const url = new URL(trimmed);
  const isHttpLoopback = url.protocol === 'http:' && isLoopbackHostname(url.hostname);
  if (url.protocol !== 'https:' && !isHttpLoopback) {
    throw new Error('baseUrl must use HTTPS (HTTP is only allowed for loopback hosts).');
  }
  url.pathname = stripTrailingSlash(url.pathname);
  return url.toString().replace(/\/+$/, '');
}

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body === 'object' && body && 'error_description' in body) {
      return String((body as Record<string, unknown>).error_description ?? response.statusText);
    }
    if (typeof body === 'object' && body && 'error' in body) {
      return String((body as Record<string, unknown>).error ?? response.statusText);
    }
  } catch {
    try {
      return await response.text();
    } catch {
      // Ignore secondary failures.
    }
  }
  return response.statusText;
}

export class AunsormOAuthClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly storage?: KeyValueStore;
  private readonly randomSource: RandomSource;
  private readonly digestFn: DigestFn;
  private readonly stateKey: string;
  private readonly verifierKey: string;
  private readonly tokenKey: string;

  constructor(options: OAuthClientOptions) {
    this.baseUrl = parseUrl(options.baseUrl);
    this.fetchImpl = ensureFetch(options.fetchImpl);
    this.storage = detectStorage(options.storage);
    this.randomSource = options.randomSource ?? defaultRandomSource;
    this.digestFn = options.digestFn ?? defaultDigestFn;
    this.stateKey = options.stateStorageKey ?? DEFAULT_STATE_KEY;
    this.verifierKey = options.verifierStorageKey ?? DEFAULT_VERIFIER_KEY;
    this.tokenKey = options.tokenStorageKey ?? DEFAULT_TOKEN_KEY;
  }

  private get verifier(): string | undefined {
    return this.storage?.getItem(this.verifierKey) ?? undefined;
  }

  private get state(): string | undefined {
    return this.storage?.getItem(this.stateKey) ?? undefined;
  }

  private persistSession(state: string, verifier: string): void {
    if (!this.storage) {
      return;
    }
    this.storage.setItem(this.stateKey, state);
    this.storage.setItem(this.verifierKey, verifier);
  }

  private clearSession(): void {
    if (!this.storage) {
      return;
    }
    this.storage.removeItem(this.stateKey);
    this.storage.removeItem(this.verifierKey);
  }

  private persistToken(token: string): void {
    if (!this.storage) {
      return;
    }
    this.storage.setItem(this.tokenKey, token);
  }

  async beginAuthorization(params: BeginAuthorizationParams): Promise<BeginAuthorizationResult> {
    const verifier = await generateCodeVerifier(DEFAULT_CODE_VERIFIER_LENGTH, this.randomSource);
    const codeChallenge = await computeCodeChallenge(verifier, this.digestFn);
    const providedState = params.state;
    const stateValue = providedState ?? (await generateState(DEFAULT_STATE_LENGTH, this.randomSource));

    if (providedState !== undefined && providedState.trim().length === 0) {
      throw new Error('state must be a non-empty string when provided.');
    }

    if (!params.clientId.trim()) {
      throw new Error('clientId is required.');
    }
    if (!params.redirectUri.trim()) {
      throw new Error('redirectUri is required.');
    }

    this.persistSession(stateValue, verifier);

    const payload: Record<string, unknown> = {
      client_id: params.clientId,
      redirect_uri: params.redirectUri,
      state: stateValue,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    };
    if (params.scope) {
      payload.scope = params.scope;
    }
    if (params.subject) {
      payload.subject = params.subject;
    }

    const response = await this.fetchImpl(`${this.baseUrl}/oauth/begin-auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      this.clearSession();
      throw new Error(`OAuth begin-auth failed: ${await readError(response)}`);
    }

    const data = (await response.json()) as {
      code?: unknown;
      state?: unknown;
      expires_in?: unknown;
    };

    if (typeof data.code !== 'string' || data.code.length === 0) {
      this.clearSession();
      throw new Error('OAuth begin-auth response missing authorization code.');
    }

    if (data.state !== undefined && data.state !== stateValue) {
      this.clearSession();
      throw new Error('State mismatch detected in begin-auth response (possible CSRF).');
    }

    const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 0;

    return {
      code: data.code,
      state: stateValue,
      expiresIn,
      codeVerifier: verifier,
    };
  }

  handleCallback(
    callback: string | URL | URLSearchParams,
    expectedStateOverride?: string,
  ): { code: string; state?: string } {
    const params =
      callback instanceof URLSearchParams
        ? callback
        : callback instanceof URL
          ? callback.searchParams
          : new URL(callback, 'https://callback.local').searchParams;

    const code = params.get('code');
    const returnedState = params.get('state') ?? undefined;

    if (!code) {
      throw new Error('Callback URL missing authorization code.');
    }

    const storedState = this.state;

    if (storedState && expectedStateOverride && expectedStateOverride !== storedState) {
      throw new Error('Provided expectedStateOverride does not match stored state value.');
    }

    const expectedState = storedState ?? expectedStateOverride;

    if (expectedState && returnedState !== expectedState) {
      throw new Error('State mismatch detected during callback handling.');
    }

    return { code, state: returnedState };
  }

  async exchangeToken(params: ExchangeTokenParams): Promise<TokenResponseBody> {
    if (!params.code.trim()) {
      throw new Error('Authorization code is required.');
    }
    if (!params.redirectUri.trim()) {
      throw new Error('redirectUri is required.');
    }
    if (!params.clientId.trim()) {
      throw new Error('clientId is required.');
    }

    const verifier = this.verifier;
    if (!verifier) {
      throw new Error('Missing PKCE code verifier in storage.');
    }

    const payload = {
      grant_type: 'authorization_code',
      code: params.code,
      code_verifier: verifier,
      client_id: params.clientId,
      redirect_uri: params.redirectUri,
    };

    const response = await this.fetchImpl(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`OAuth token exchange failed: ${await readError(response)}`);
    }

    const body = (await response.json()) as TokenResponseBody;
    if (!body || typeof body.access_token !== 'string' || body.access_token.length === 0) {
      throw new Error('OAuth token response missing access_token.');
    }

    this.persistToken(body.access_token);
    this.clearSession();
    return body;
  }

  getStoredAccessToken(): string | undefined {
    return this.storage?.getItem(this.tokenKey) ?? undefined;
  }

  clearStoredAccessToken(): void {
    if (!this.storage) {
      return;
    }
    this.storage.removeItem(this.tokenKey);
  }
}

export class MemoryStore implements KeyValueStore {
  private readonly map = new Map<string, string>();

  getItem(key: string): string | null {
    return this.map.has(key) ? this.map.get(key)! : null;
  }

  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }

  removeItem(key: string): void {
    this.map.delete(key);
  }
}
