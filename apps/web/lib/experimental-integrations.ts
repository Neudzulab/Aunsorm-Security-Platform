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

const LOOPBACK_HOST_ALIASES = new Set([
  'localhost.localdomain',
  'localhost6',
  'localhost6.localdomain6',
  'ip6-localhost',
  'ip6-loopback',
]);

type FileReader = (filePath: string) => string;

const defaultReadFile: FileReader = (filePath) => readFileSync(filePath, 'utf8');

interface HostPortParts {
  host: string;
  port?: string;
  hadBrackets: boolean;
  rest: string;
}

function stripTrailingDots(host: string): string {
  if (host.length === 0) {
    return host;
  }

  const withoutDots = host.replace(/\.+$/, '');
  return withoutDots.length > 0 ? withoutDots : host;
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
      const host = stripTrailingDots(hostPort.slice(1, closing));
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

      return {
        host,
        hadBrackets: true,
        rest: hostPortEnd === -1 ? '' : trimmed.slice(hostPortEnd),
      };
    }
  }

  const lastColon = hostPort.lastIndexOf(':');
  if (lastColon > 0) {
    const maybePort = hostPort.slice(lastColon + 1);
    if (/^\d+$/.test(maybePort)) {
      const hostCandidate = stripTrailingDots(hostPort.slice(0, lastColon));
      const isIpv4OrHostname = !hostCandidate.includes(':');
      const isIpv4MappedIpv6 = hostCandidate.includes(':') && hostCandidate.includes('.');
      const isHexIpv4Mapped =
        hostCandidate.startsWith('::ffff:') &&
        decodeHexIpv4Mapped(hostCandidate.slice('::ffff:'.length)) !== undefined;

      if (isIpv4OrHostname || isIpv4MappedIpv6 || isHexIpv4Mapped) {
        return {
          host: hostCandidate,
          port: maybePort,
          hadBrackets: false,
          rest,
        };
      }
    }
  }

  return { host: stripTrailingDots(hostPort), hadBrackets: false, rest };
}

function isLoopbackIpv4Address(candidate: string): boolean {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(candidate)) {
    return false;
  }

  const segments = candidate.split('.');
  if (segments.length !== 4) {
    return false;
  }

  const numbers = segments.map((segment) => Number(segment));
  if (numbers.some((segment) => Number.isNaN(segment) || segment < 0 || segment > 255)) {
    return false;
  }

  if (numbers[0] === 127) {
    return true;
  }

  return numbers.every((segment) => segment === 0);
}

function decodeHexIpv4Mapped(mapped: string): string | undefined {
  const segments = mapped.split(':').filter((segment) => segment.length > 0);
  if (segments.length !== 2) {
    return undefined;
  }

  if (!segments.every((segment) => /^[0-9a-f]{1,4}$/i.test(segment))) {
    return undefined;
  }

  const [highSegment, lowSegment] = segments;
  const high = Number.parseInt(highSegment, 16);
  const low = Number.parseInt(lowSegment, 16);

  if (Number.isNaN(high) || Number.isNaN(low)) {
    return undefined;
  }

  const bytes = [
    (high >> 8) & 0xff,
    high & 0xff,
    (low >> 8) & 0xff,
    low & 0xff,
  ];

  return bytes.join('.');
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

function removeDotSegments(pathValue: string): string {
  if (pathValue === '') {
    return '';
  }

  const leadingSlash = pathValue.startsWith('/');
  const trailingSlash = pathValue.endsWith('/');
  const segments = pathValue.split('/');
  const output: string[] = [];

  for (const segment of segments) {
    if (segment === '' || segment === '.') {
      continue;
    }

    if (segment === '..') {
      if (output.length > 0) {
        output.pop();
      }
      continue;
    }

    output.push(segment);
  }

  let normalised = output.join('/');

  if (leadingSlash) {
    normalised = `/${normalised}`;
  }

  if (normalised === '' && leadingSlash) {
    return '/';
  }

  if (trailingSlash && normalised !== '' && !normalised.endsWith('/')) {
    return `${normalised}/`;
  }

  return normalised;
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
  const dotFree = removeDotSegments(collapsed);

  if (dotFree === '' || dotFree === '/') {
    return '/';
  }

  if (hasTrailingSlash) {
    return dotFree.endsWith('/') ? dotFree : `${dotFree}/`;
  }

  return dotFree.endsWith('/') ? dotFree.replace(/\/+$/, '') : dotFree;
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
      const canonical = stripTrailingDots(normalised);
      return canonical.length > 0 ? canonical.toLowerCase() : undefined;
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
  const canonical = stripTrailingDots(normalised);

  return canonical.length > 0 ? canonical.toLowerCase() : undefined;
}

function isLoopbackHost(value: string | undefined): boolean {
  const hostname = extractHostname(value);
  if (!hostname) {
    return false;
  }

  if (LOOPBACK_HOST_ALIASES.has(hostname)) {
    return true;
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
    if (isLoopbackIpv4Address(mapped)) {
      return true;
    }

    const decoded = decodeHexIpv4Mapped(mapped);
    if (decoded) {
      return isLoopbackIpv4Address(decoded);
    }

    return false;
  }

  if (isLoopbackIpv4Address(hostname)) {
    return true;
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

  const trimmedInput = baseUrl.trim();
  const hadExplicitTrailingSlash = trimmedInput.endsWith('/');
  const fallbackScheme: 'http' | 'https' = isLoopbackHost(baseUrl) ? 'http' : 'https';
  const candidate = ensureProtocol(baseUrl, fallbackScheme);

  try {
    const url = new URL(candidate);
    const pathWithQueryAndFragment = `${url.pathname}${url.search}${url.hash}`;
    const path =
      pathWithQueryAndFragment === '/' && !hadExplicitTrailingSlash
        ? ''
        : pathWithQueryAndFragment;
    return {
      origin: url.origin,
      path,
    };
  } catch {
    return { origin: baseUrl, path: '' };
  }
}
