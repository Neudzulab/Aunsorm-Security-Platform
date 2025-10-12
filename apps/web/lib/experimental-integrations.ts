import { readFileSync } from 'node:fs';

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

const DIRECT_BASE_URL_FILE_KEYS = [
  'NEXT_PUBLIC_AUNSORM_BASE_URL_FILE',
  'AUNSORM_BASE_URL_FILE',
  'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_BASE_URL_FILE',
  'AUNSORM_INTEGRATIONS_BASE_URL_FILE',
];

const DOMAIN_KEYS = [
  'NEXT_PUBLIC_AUNSORM_BASE_DOMAIN',
  'AUNSORM_BASE_DOMAIN',
  'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_DOMAIN',
  'AUNSORM_INTEGRATIONS_DOMAIN',
  // Common deployment provider aliases so hosted previews Just Work.
  'NEXT_PUBLIC_VERCEL_URL',
  'VERCEL_URL',
  'NEXT_PUBLIC_VERCEL_BRANCH_URL',
  'VERCEL_BRANCH_URL',
  'NEXT_PUBLIC_VERCEL_PROJECT_PRODUCTION_URL',
  'VERCEL_PROJECT_PRODUCTION_URL',
  'NEXT_PUBLIC_DEPLOYMENT_URL',
  'DEPLOYMENT_URL',
];

const PATH_KEYS = [
  'NEXT_PUBLIC_AUNSORM_BASE_PATH',
  'AUNSORM_BASE_PATH',
  'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_PATH',
  'AUNSORM_INTEGRATIONS_PATH',
];

type FileReader = (filePath: string) => string;

const defaultReadFile: FileReader = (filePath) => readFileSync(filePath, 'utf8');

interface HostPortParts {
  host: string;
  port?: string;
  hadBrackets: boolean;
  rest: string;
}

function splitHostPort(value: string): HostPortParts {
  const trimmed = value.trim();

  if (trimmed.length === 0) {
    return { host: '', hadBrackets: false, rest: '' };
  }

  const hostPortEnd = trimmed.search(/[/?#]/);
  const hostPort = hostPortEnd === -1 ? trimmed : trimmed.slice(0, hostPortEnd);
  const rest = hostPortEnd === -1 ? '' : trimmed.slice(hostPortEnd);

  if (hostPort.startsWith('[')) {
    const closing = hostPort.indexOf(']');
    if (closing !== -1) {
      const host = hostPort.slice(1, closing);
      const rest = hostPort.slice(closing + 1);
      if (rest.startsWith(':')) {
        const portCandidate = rest.slice(1);
        if (/^\d+$/.test(portCandidate)) {
          return {
            host,
            port: portCandidate,
            hadBrackets: true,
            rest: hostPortEnd === -1 ? '' : trimmed.slice(hostPortEnd),
          };
        }
      }

      return { host, hadBrackets: true, rest: hostPortEnd === -1 ? '' : trimmed.slice(hostPortEnd) };
    }
  }

  const lastColon = hostPort.lastIndexOf(':');
  if (lastColon > 0) {
    const maybePort = hostPort.slice(lastColon + 1);
    if (/^\d+$/.test(maybePort)) {
      const hostCandidate = hostPort.slice(0, lastColon);
      const isIpv4OrHostname = !hostCandidate.includes(':');
      const isIpv4MappedIpv6 = hostCandidate.includes(':') && hostCandidate.includes('.');

      if (isIpv4OrHostname || isIpv4MappedIpv6) {
        return {
          host: hostCandidate,
          port: maybePort,
          hadBrackets: false,
          rest,
        };
      }
    }
  }

  return { host: hostPort, hadBrackets: false, rest };
}

interface ReadResult {
  found: boolean;
  value?: string;
  key?: string;
  filePath?: string;
}

interface DirectBaseComponents {
  origin: string;
  path: string;
}

function readEnvValue(keys: string[], env: NodeJS.ProcessEnv): ReadResult {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(env, key)) {
      const raw = env[key];
      if (raw === undefined || raw === null) {
        return { found: true, value: '', key };
      }

      const trimmed = raw.trim();
      if (trimmed.length === 0) {
        return { found: true, value: '', key };
      }

      return { found: true, value: trimmed, key };
    }
  }

  return { found: false };
}

function readEnvFileValue(
  keys: string[],
  env: NodeJS.ProcessEnv,
  readFile: FileReader,
): ReadResult {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(env, key)) {
      const rawPath = env[key];
      if (rawPath === undefined || rawPath === null) {
        return { found: true, value: '', key };
      }

      const trimmedPath = rawPath.trim();
      if (trimmedPath.length === 0) {
        return { found: true, value: '', key };
      }

      try {
        const contents = readFile(trimmedPath);
        const value = contents.trim();
        return {
          found: true,
          value,
          key,
          filePath: trimmedPath,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Failed to read ${key} (${trimmedPath}): ${message}`);
      }
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
  const withoutSlashes = origin.startsWith('//') ? origin.replace(/^\/+/, '') : origin;
  const { host, port, hadBrackets, rest } = splitHostPort(withoutSlashes);

  if (host.length === 0) {
    return scheme;
  }

  const shouldBracket = host.includes(':');
  const bracketedHost = hadBrackets || shouldBracket ? `[${host}]` : host;
  const portSuffix = port ? `:${port}` : '';

  return `${scheme}${bracketedHost}${portSuffix}${rest}`;
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

  const protocolRelative =
    trimmed.startsWith('//') && !/^https?:\/\//i.test(trimmed) ? `http:${trimmed}` : trimmed;

  if (/^\w+:\/\//i.test(protocolRelative)) {
    try {
      const url = new URL(protocolRelative);
      const host = url.hostname;
      const normalised = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
      return normalised.toLowerCase();
    } catch {
      return undefined;
    }
  }

  const withoutSlashes = trimmed.startsWith('//') ? trimmed.replace(/^\/+/, '') : trimmed;
  const { host } = splitHostPort(withoutSlashes);

  if (host.length === 0) {
    return undefined;
  }

  const normalised = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;

  return normalised.toLowerCase();
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

  if (
    hostname === '::' ||
    hostname === '::0' ||
    hostname === '0:0:0:0:0:0:0:0'
  ) {
    return true;
  }

  if (hostname.startsWith('::ffff:')) {
    const mapped = hostname.slice('::ffff:'.length);
    return (
      mapped.startsWith('127.') ||
      mapped === '127.0.0.1' ||
      mapped === '0.0.0.0'
    );
  }

  if (hostname === '0.0.0.0') {
    return true;
  }

  if (hostname.startsWith('127.')) {
    const parts = hostname.split('.');
    if (parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) <= 255)) {
      return true;
    }
  }

  return false;
}

export function resolveAunsormBaseUrl(
  env: NodeJS.ProcessEnv = process.env,
  readFile: FileReader = defaultReadFile,
): string {
  const details = resolveAunsormBaseUrlDetails(env, readFile);
  if (!details.origin) {
    return details.baseUrl;
  }

  return joinUrl(details.origin, details.path);
}

export type AunsormBaseUrlSource =
  | {
      kind: 'direct';
      key?: string;
    }
  | {
      kind: 'direct-file';
      key?: string;
      filePath?: string;
    }
  | {
      kind: 'domain-path';
      domainKey?: string;
      pathKey?: string;
    }
  | {
      kind: 'default';
      nodeEnv: 'production' | 'other';
    };

export interface AunsormBaseUrlDetails {
  baseUrl: string;
  origin: string;
  path: string;
  source: AunsormBaseUrlSource;
}

export function resolveAunsormBaseUrlDetails(
  env: NodeJS.ProcessEnv = process.env,
  readFile: FileReader = defaultReadFile,
): AunsormBaseUrlDetails {
  const directFromFile = readEnvFileValue(DIRECT_BASE_URL_FILE_KEYS, env, readFile);
  if (directFromFile.found) {
    const directFileValue = directFromFile.value ?? '';
    const components = deriveDirectBaseComponents(directFileValue);
    return {
      baseUrl: directFileValue,
      origin: components.origin,
      path: components.path,
      source: {
        kind: 'direct-file',
        key: directFromFile.key,
        filePath: directFromFile.filePath,
      },
    };
  }

  const direct = readEnvValue(DIRECT_BASE_URL_KEYS, env);
  if (direct.found) {
    const directValue = direct.value ?? '';
    const components = deriveDirectBaseComponents(directValue);
    return {
      baseUrl: directValue,
      origin: components.origin,
      path: components.path,
      source: {
        kind: 'direct',
        key: direct.key,
      },
    };
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
    return {
      baseUrl: joinUrl(resolvedOrigin, resolvedPath),
      origin: resolvedOrigin,
      path: resolvedPath,
      source: {
        kind: 'domain-path',
        domainKey: domain.key,
        pathKey: path.key,
      },
    };
  }

  return {
    baseUrl: joinUrl(fallbackDefaults.origin, fallbackDefaults.path),
    origin: fallbackDefaults.origin,
    path: fallbackDefaults.path,
    source: {
      kind: 'default',
      nodeEnv,
    },
  };
}

function deriveDirectBaseComponents(baseUrl: string): DirectBaseComponents {
  if (baseUrl === '') {
    return { origin: '', path: '' };
  }

  const fallbackScheme: 'http' | 'https' = isLoopbackHost(baseUrl) ? 'http' : 'https';
  const candidate = ensureProtocol(baseUrl, fallbackScheme);

  try {
    const url = new URL(candidate);
    const pathWithQueryAndFragment = `${url.pathname}${url.search}${url.hash}`;
    return {
      origin: url.origin,
      path: pathWithQueryAndFragment.length > 0 ? pathWithQueryAndFragment : '',
    };
  } catch {
    return { origin: baseUrl, path: '' };
  }
}
