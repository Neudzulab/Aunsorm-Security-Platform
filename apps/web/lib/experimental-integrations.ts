const DEFAULTS = {
  local: {
    origin: 'http://localhost:50047',
    path: '/aunsorm',
  },
  production: {
    origin: 'https://aunsorm.dev',
    path: '/aunsorm',
  },
} as const;

const DIRECT_BASE_URL_KEYS = [
  'NEXT_PUBLIC_AUNSORM_BASE_URL',
  'AUNSORM_BASE_URL',
  'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_BASE_URL',
  'AUNSORM_INTEGRATIONS_BASE_URL',
];

const DOMAIN_KEYS = [
  'NEXT_PUBLIC_AUNSORM_BASE_DOMAIN',
  'AUNSORM_BASE_DOMAIN',
  'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_DOMAIN',
  'AUNSORM_INTEGRATIONS_DOMAIN',
];

const PATH_KEYS = [
  'NEXT_PUBLIC_AUNSORM_BASE_PATH',
  'AUNSORM_BASE_PATH',
  'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_PATH',
  'AUNSORM_INTEGRATIONS_PATH',
];

interface ReadResult {
  found: boolean;
  value?: string;
}

function readEnvValue(keys: string[], env: NodeJS.ProcessEnv): ReadResult {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(env, key)) {
      const raw = env[key];
      if (raw === undefined || raw === null) {
        return { found: true, value: '' };
      }

      const trimmed = raw.trim();
      if (trimmed.length === 0) {
        return { found: true, value: '' };
      }

      return { found: true, value: trimmed };
    }
  }

  return { found: false };
}

function ensureProtocol(origin: string, fallbackScheme: 'http' | 'https'): string {
  if (origin === '') {
    return '';
  }

  if (/^https?:\/\//i.test(origin)) {
    return origin;
  }

  const scheme = fallbackScheme === 'https' ? 'https://' : 'http://';
  const colonCount = (origin.match(/:/g) ?? []).length;
  const needsIpv6Brackets = colonCount > 1 && !origin.startsWith('[');
  const normalisedOrigin = needsIpv6Brackets ? `[${origin}]` : origin;

  return `${scheme}${normalisedOrigin}`;
}

function collapseSlashes(input: string): string {
  return input.replace(/\/{2,}/g, '/');
}

function normalisePath(pathValue: string | undefined, defaultPath: string): string {
  if (pathValue === undefined) {
    return defaultPath;
  }

  if (pathValue === '') {
    return '';
  }

  const hasTrailingSlash = pathValue.endsWith('/');
  const withLeadingSlash = pathValue.startsWith('/') ? pathValue : `/${pathValue}`;
  const collapsed = collapseSlashes(withLeadingSlash);

  if (collapsed === '/') {
    return '/';
  }

  if (hasTrailingSlash) {
    return collapsed.endsWith('/') ? collapsed : `${collapsed}/`;
  }

  return collapsed.endsWith('/') ? collapsed.replace(/\/+$/, '') : collapsed;
}

function joinUrl(origin: string, path: string): string {
  if (!origin) {
    return path;
  }

  if (!path) {
    return origin.replace(/\/$/, '');
  }

  const normalisedOrigin = origin.replace(/\/$/, '');
  const normalisedPath = path.startsWith('/') ? path : `/${path}`;

  return `${normalisedOrigin}${normalisedPath}`;
}

function resolveNodeEnv(env: NodeJS.ProcessEnv): 'production' | 'other' {
  const raw = env.NODE_ENV;
  if (!raw) {
    return 'other';
  }

  return raw.trim().toLowerCase() === 'production' ? 'production' : 'other';
}

function extractHostname(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return undefined;
  }

  const colonCount = (trimmed.match(/:/g) ?? []).length;
  const maybeIpv6 = colonCount > 1 && !/^\w+:\/\//i.test(trimmed);
  const bracketed = maybeIpv6 && !trimmed.startsWith('[') ? `[${trimmed}]` : trimmed;
  const candidate = /^\w+:\/\//i.test(bracketed) ? bracketed : `http://${bracketed}`;

  try {
    const url = new URL(candidate);
    let host = url.hostname;
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.slice(1, -1);
    }
    return host.toLowerCase();
  } catch {
    return undefined;
  }
}

function isLoopbackHost(value: string | undefined): boolean {
  const hostname = extractHostname(value);
  if (!hostname) {
    return false;
  }

  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return true;
  }

  if (hostname === '::1' || hostname === '0:0:0:0:0:0:0:1') {
    return true;
  }

  if (hostname.startsWith('::ffff:')) {
    const mapped = hostname.slice('::ffff:'.length);
    return mapped.startsWith('127.') || mapped === '127.0.0.1';
  }

  if (hostname.startsWith('127.')) {
    const parts = hostname.split('.');
    if (parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) <= 255)) {
      return true;
    }
  }

  return false;
}

export function resolveAunsormBaseUrl(env: NodeJS.ProcessEnv = process.env): string {
  const direct = readEnvValue(DIRECT_BASE_URL_KEYS, env);
  if (direct.found) {
    return direct.value ?? '';
  }

  const nodeEnv = resolveNodeEnv(env);
  const fallbackDefaults = nodeEnv === 'production' ? DEFAULTS.production : DEFAULTS.local;

  const domain = readEnvValue(DOMAIN_KEYS, env);
  const path = readEnvValue(PATH_KEYS, env);

  if (domain.found || path.found) {
    const scheme: 'http' | 'https' = isLoopbackHost(domain.value)
      ? 'http'
      : nodeEnv === 'production'
        ? 'https'
        : 'http';
    const domainOverride = domain.value;
    const hasDomainOverride =
      domainOverride !== undefined && domainOverride.length > 0;
    const resolvedOrigin = ensureProtocol(
      hasDomainOverride ? domainOverride : fallbackDefaults.origin,
      scheme,
    );
    const resolvedPath = normalisePath(path.value, fallbackDefaults.path);
    return joinUrl(resolvedOrigin, resolvedPath);
  }

  return joinUrl(fallbackDefaults.origin, fallbackDefaults.path);
}
