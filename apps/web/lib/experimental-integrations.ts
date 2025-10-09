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
  return `${scheme}${origin}`;
}

function normalisePath(pathValue: string | undefined, defaultPath: string): string {
  if (pathValue === undefined) {
    return defaultPath;
  }

  if (pathValue === '') {
    return '';
  }

  if (pathValue.startsWith('/')) {
    return pathValue;
  }

  return `/${pathValue}`;
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
    const scheme: 'http' | 'https' = domain.value && /localhost|127\.0\.0\.1/i.test(domain.value)
      ? 'http'
      : nodeEnv === 'production'
        ? 'https'
        : 'http';
    const resolvedOrigin = ensureProtocol(
      domain.value ?? fallbackDefaults.origin,
      scheme,
    );
    const resolvedPath = normalisePath(path.value, fallbackDefaults.path);
    return joinUrl(resolvedOrigin, resolvedPath);
  }

  return joinUrl(fallbackDefaults.origin, fallbackDefaults.path);
}
