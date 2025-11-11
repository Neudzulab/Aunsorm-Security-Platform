import { describe, expect, it, vi } from 'vitest';

import {
  resolveAunsormBaseUrl,
  resolveAunsormBaseUrlDetails,
  resolveAunsormBaseUrlDiagnostics,
} from './experimental-integrations.js';

describe('resolveAunsormBaseUrl', () => {
  it('returns direct base url when an explicit variable is provided', () => {
    const env = {
      NEXT_PUBLIC_AUNSORM_BASE_URL: 'https://example.invalid/custom',
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://example.invalid/custom');
  });

  it('preserves direct overrides without adding a trailing slash when no path is provided', () => {
    const env = {
      AUNSORM_BASE_URL: 'https://example.invalid',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://example.invalid');
  });

  it('treats blank direct values as empty strings', () => {
    const env = {
      NEXT_PUBLIC_AUNSORM_BASE_URL: '   ',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('');
  });

  it('prefers file-based overrides when present', () => {
    const env = {
      AUNSORM_BASE_URL_FILE: '/secrets/base-url',
      AUNSORM_BASE_URL: 'https://example.invalid/should-not-be-used',
    } satisfies NodeJS.ProcessEnv;

    const stub = vi.fn(() => 'https://file.example.invalid/from-file');

    expect(resolveAunsormBaseUrl(env, stub)).toBe('https://file.example.invalid/from-file');
    expect(stub).toHaveBeenCalledWith('/secrets/base-url');
  });

  it('normalises protocol-relative direct overrides using the fallback scheme', () => {
    const env = {
      AUNSORM_BASE_URL: '//example.invalid/custom',
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://example.invalid/custom');
  });

  it('normalises IPv4-mapped IPv6 direct overrides with inline ports', () => {
    const env = {
      AUNSORM_BASE_URL: '::ffff:127.0.0.1:4100/custom',
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::ffff:7f00:1]:4100/custom');
  });

  it('detects loopback hosts in protocol-relative direct overrides', () => {
    const env = {
      AUNSORM_BASE_URL: '//localhost:3100/callback',
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://localhost:3100/callback');
  });

  it('treats blank file paths as empty overrides', () => {
    const env = {
      AUNSORM_BASE_URL_FILE: '   ',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env, () => 'ignored')).toBe('');
  });

  it('propagates file read errors with helpful context', () => {
    const env = {
      AUNSORM_BASE_URL_FILE: '/missing/file',
    } satisfies NodeJS.ProcessEnv;

    const failingStub = vi.fn(() => {
      throw new Error('ENOENT: no such file or directory');
    });

    expect(() => resolveAunsormBaseUrl(env, failingStub)).toThrowError(
      /Failed to read AUNSORM_BASE_URL_FILE \(\/missing\/file\): ENOENT: no such file or directory/,
    );
  });

  it('builds the url from domain and path overrides', () => {
    const env = {
      NEXT_PUBLIC_AUNSORM_BASE_DOMAIN: 'api.aunsorm.dev',
      NEXT_PUBLIC_AUNSORM_BASE_PATH: 'bridge/v1',
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://api.aunsorm.dev/bridge/v1');
  });

  it('forces http when the domain is a localhost host even in production', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: 'localhost:3100',
      AUNSORM_INTEGRATIONS_PATH: 'callback',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://localhost:3100/callback');
  });

  it('forces http when the domain is a localhost alias hostname', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: 'localhost.localdomain',
      AUNSORM_INTEGRATIONS_PATH: 'callback',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://localhost.localdomain/callback');

    const ipv6Alias = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: 'ip6-localhost:4100',
      AUNSORM_INTEGRATIONS_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(ipv6Alias)).toBe('http://ip6-localhost:4100/bridge');
  });

  it('forces http when the domain points at an IPv6 loopback host', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '[::1]:4100',
      AUNSORM_INTEGRATIONS_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::1]:4100/bridge');

    const bareLoopback = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '::1',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(bareLoopback)).toBe('http://[::1]/aunsorm');
  });

  it('percent-encodes IPv6 zone identifiers in domain overrides', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '::1%lo0:4100',
      AUNSORM_INTEGRATIONS_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::1%25lo0]:4100/bridge');

    const alreadyEncoded = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '::1%25lo0:4100',
      AUNSORM_INTEGRATIONS_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(alreadyEncoded)).toBe('http://[::1%25lo0]:4100/bridge');
  });

  it('normalises loopback domains with trailing dots', () => {
    const localhostWithDot = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'localhost.',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(localhostWithDot)).toBe('http://localhost/aunsorm');

    const subdomainWithDot = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'preview.localhost.',
      AUNSORM_BASE_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(subdomainWithDot)).toBe('http://preview.localhost/bridge');
  });

  it('treats unspecified IP addresses as loopback and forces http', () => {
    const ipv4Unspecified = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '0.0.0.0:4500',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(ipv4Unspecified)).toBe('http://0.0.0.0:4500/aunsorm');

    const ipv6Unspecified = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '[::]:5500',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(ipv6Unspecified)).toBe('http://[::]:5500/aunsorm');
  });

  it('treats hex-encoded IPv4-mapped loopback domains as http', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '::ffff:7f00:1:4600',
      AUNSORM_INTEGRATIONS_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::ffff:7f00:1]:4600/bridge');
  });

  it('falls back to local defaults when nothing is set', () => {
    const env = {} satisfies NodeJS.ProcessEnv;
    expect(resolveAunsormBaseUrl(env)).toBe('http://localhost:50047/aunsorm');
  });

  it('uses production defaults when NODE_ENV=production', () => {
    const env = {
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://aunsorm.dev/aunsorm');
  });

  it('normalises relative paths by prepending a slash', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev',
      AUNSORM_BASE_PATH: 'api',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://gateway.aunsorm.dev/api');
  });

  it('falls back to defaults when the domain override is blank but a path is provided', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: '   ',
      AUNSORM_BASE_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://aunsorm.dev/bridge');
  });

  it('applies scheme heuristics to protocol-relative domain overrides', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: '//gateway.aunsorm.dev',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://gateway.aunsorm.dev/aunsorm');
  });

  it('treats protocol-relative IPv6 loopback domain overrides as http', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '//[::1]:4100',
      AUNSORM_INTEGRATIONS_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::1]:4100/bridge');
  });

  it('normalises IPv4-mapped IPv6 domains with inline ports', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: '::ffff:127.0.0.1:4100',
      AUNSORM_BASE_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::ffff:127.0.0.1]:4100/bridge');
  });

  it('recognises deployment provider domain aliases such as Vercel', () => {
    const env = {
      NODE_ENV: 'production',
      VERCEL_URL: 'preview-aunsorm.vercel.app',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://preview-aunsorm.vercel.app/aunsorm');
  });

  it('recognises additional Vercel deployment aliases', () => {
    const envBranch = {
      NODE_ENV: 'production',
      VERCEL_BRANCH_URL: 'branch-aunsorm.vercel.app',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(envBranch)).toBe('https://branch-aunsorm.vercel.app/aunsorm');

    const envProject = {
      NODE_ENV: 'production',
      VERCEL_PROJECT_PRODUCTION_URL: 'prod-aunsorm.vercel.app',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(envProject)).toBe('https://prod-aunsorm.vercel.app/aunsorm');
  });

  it('removes trailing slash when the path override is empty', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev/',
      AUNSORM_BASE_PATH: '',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://gateway.aunsorm.dev');
  });

  it('collapses duplicate slashes in path overrides while respecting trailing slash intent', () => {
    const envWithTrailing = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev',
      AUNSORM_BASE_PATH: '//bridge///v1//',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(envWithTrailing)).toBe('https://gateway.aunsorm.dev/bridge/v1/');

    const envSingle = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev',
      AUNSORM_BASE_PATH: '///bridge///v1',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(envSingle)).toBe('https://gateway.aunsorm.dev/bridge/v1');

    const envRoot = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev',
      AUNSORM_BASE_PATH: '////',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(envRoot)).toBe('https://gateway.aunsorm.dev/');
  });

  it('normalises dot segments in path overrides to prevent directory traversal', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev',
      AUNSORM_BASE_PATH: './bridge/../v1/./next/',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://gateway.aunsorm.dev/v1/next/');

    const envAscending = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev',
      AUNSORM_BASE_PATH: '../../',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(envAscending)).toBe('https://gateway.aunsorm.dev/');
  });

  it('normalises direct overrides with hex-encoded IPv4-mapped loopback hosts', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_URL: '::ffff:7f00:1:4700/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::ffff:7f00:1]:4700/custom');
  });

  it('normalises direct overrides with localhost alias hostnames', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_URL: 'localhost6:3200/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://localhost6:3200/custom');
  });

  it('supports direct overrides with IPv6 zone identifiers', () => {
    const env = {
      AUNSORM_BASE_URL: '::1%lo0:4700/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('http://[::1%25lo0]:4700/custom');

    const alreadyEncoded = {
      AUNSORM_BASE_URL: '::1%25lo0:4700/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(alreadyEncoded)).toBe('http://[::1%25lo0]:4700/custom');
  });
});

describe('resolveAunsormBaseUrlDetails', () => {
  it('reports direct overrides with the source key', () => {
    const env = {
      AUNSORM_BASE_URL: 'https://example.invalid/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'https://example.invalid/custom',
      origin: 'https://example.invalid',
      path: '/custom',
      source: {
        kind: 'direct',
        key: 'AUNSORM_BASE_URL',
      },
    });
  });

  it('reports empty paths for direct overrides that do not specify one', () => {
    const env = {
      AUNSORM_BASE_URL: 'https://example.invalid',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'https://example.invalid',
      origin: 'https://example.invalid',
      path: '',
      source: {
        kind: 'direct',
        key: 'AUNSORM_BASE_URL',
      },
    });
  });

  it('reports file-based overrides including the file path', () => {
    const env = {
      NEXT_PUBLIC_AUNSORM_BASE_URL_FILE: '/etc/aunsorm/base-url',
    } satisfies NodeJS.ProcessEnv;

    const stub = vi.fn(() => 'https://file.example.invalid/custom');

    expect(resolveAunsormBaseUrlDetails(env, stub)).toEqual({
      baseUrl: 'https://file.example.invalid/custom',
      origin: 'https://file.example.invalid',
      path: '/custom',
      source: {
        kind: 'direct-file',
        key: 'NEXT_PUBLIC_AUNSORM_BASE_URL_FILE',
        filePath: '/etc/aunsorm/base-url',
      },
    });
  });

  it('reports encoded origins for domain overrides with IPv6 zone identifiers', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_INTEGRATIONS_DOMAIN: '::1%lo0:4100',
      AUNSORM_INTEGRATIONS_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'http://[::1%25lo0]:4100/bridge',
      origin: 'http://[::1%25lo0]:4100',
      path: '/bridge',
      source: {
        kind: 'domain-path',
        domainKey: 'AUNSORM_INTEGRATIONS_DOMAIN',
        pathKey: 'AUNSORM_INTEGRATIONS_PATH',
      },
    });
  });

  it('reports encoded origins for direct overrides with IPv6 zone identifiers', () => {
    const env = {
      AUNSORM_BASE_URL: '::1%lo0:4700/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: '::1%lo0:4700/custom',
      origin: 'http://[::1%25lo0]:4700',
      path: '/custom',
      source: {
        kind: 'direct',
        key: 'AUNSORM_BASE_URL',
      },
    });
  });

  it('derives origin and path for direct overrides without a scheme', () => {
    const env = {
      AUNSORM_BASE_URL: 'localhost:3100/callback?debug=1',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'localhost:3100/callback?debug=1',
      origin: 'http://localhost:3100',
      path: '/callback?debug=1',
      source: {
        kind: 'direct',
        key: 'AUNSORM_BASE_URL',
      },
    });
  });

  it('captures the keys used when resolving from domain/path', () => {
    const env = {
      NODE_ENV: 'production',
      NEXT_PUBLIC_AUNSORM_INTEGRATIONS_DOMAIN: 'localhost:3100',
      NEXT_PUBLIC_AUNSORM_INTEGRATIONS_PATH: 'callback',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'http://localhost:3100/callback',
      origin: 'http://localhost:3100',
      path: '/callback',
      source: {
        kind: 'domain-path',
        domainKey: 'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_DOMAIN',
        pathKey: 'NEXT_PUBLIC_AUNSORM_INTEGRATIONS_PATH',
      },
    });
  });

  it('reports deployment alias keys when used as a domain override', () => {
    const env = {
      NODE_ENV: 'production',
      VERCEL_URL: 'preview-aunsorm.vercel.app',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'https://preview-aunsorm.vercel.app/aunsorm',
      origin: 'https://preview-aunsorm.vercel.app',
      path: '/aunsorm',
      source: {
        kind: 'domain-path',
        domainKey: 'VERCEL_URL',
        pathKey: undefined,
      },
    });
  });

  it('reports additional Vercel alias keys when present', () => {
    const envBranch = {
      NODE_ENV: 'production',
      VERCEL_BRANCH_URL: 'branch-aunsorm.vercel.app',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(envBranch)).toEqual({
      baseUrl: 'https://branch-aunsorm.vercel.app/aunsorm',
      origin: 'https://branch-aunsorm.vercel.app',
      path: '/aunsorm',
      source: {
        kind: 'domain-path',
        domainKey: 'VERCEL_BRANCH_URL',
        pathKey: undefined,
      },
    });

    const envProject = {
      NODE_ENV: 'production',
      VERCEL_PROJECT_PRODUCTION_URL: 'prod-aunsorm.vercel.app',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(envProject)).toEqual({
      baseUrl: 'https://prod-aunsorm.vercel.app/aunsorm',
      origin: 'https://prod-aunsorm.vercel.app',
      path: '/aunsorm',
      source: {
        kind: 'domain-path',
        domainKey: 'VERCEL_PROJECT_PRODUCTION_URL',
        pathKey: undefined,
      },
    });
  });

  it('reports hex-encoded IPv4-mapped loopback domains as http origins', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: '::ffff:7f00:1:4800',
      AUNSORM_BASE_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'http://[::ffff:7f00:1]:4800/bridge',
      origin: 'http://[::ffff:7f00:1]:4800',
      path: '/bridge',
      source: {
        kind: 'domain-path',
        domainKey: 'AUNSORM_BASE_DOMAIN',
        pathKey: 'AUNSORM_BASE_PATH',
      },
    });
  });

  it('reports IPv4-mapped IPv6 overrides with inline ports', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: '::ffff:127.0.0.1:4100',
      AUNSORM_BASE_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'http://[::ffff:127.0.0.1]:4100/bridge',
      origin: 'http://[::ffff:127.0.0.1]:4100',
      path: '/bridge',
      source: {
        kind: 'domain-path',
        domainKey: 'AUNSORM_BASE_DOMAIN',
        pathKey: 'AUNSORM_BASE_PATH',
      },
    });
  });

  it('reports localhost alias hostnames as http origins', () => {
    const domainAlias = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'localhost.localdomain',
      AUNSORM_BASE_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(domainAlias)).toEqual({
      baseUrl: 'http://localhost.localdomain/bridge',
      origin: 'http://localhost.localdomain',
      path: '/bridge',
      source: {
        kind: 'domain-path',
        domainKey: 'AUNSORM_BASE_DOMAIN',
        pathKey: 'AUNSORM_BASE_PATH',
      },
    });

    const directAlias = {
      NODE_ENV: 'production',
      AUNSORM_BASE_URL: 'localhost6:3200/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(directAlias)).toEqual({
      baseUrl: 'localhost6:3200/custom',
      origin: 'http://localhost6:3200',
      path: '/custom',
      source: {
        kind: 'direct',
        key: 'AUNSORM_BASE_URL',
      },
    });
  });

  it('reports normalised origins for trailing-dot direct overrides', () => {
    const env = {
      AUNSORM_BASE_URL: 'localhost.:3100/callback',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'localhost.:3100/callback',
      origin: 'http://localhost:3100',
      path: '/callback',
      source: {
        kind: 'direct',
        key: 'AUNSORM_BASE_URL',
      },
    });
  });

  it('reports direct overrides for IPv4-mapped IPv6 addresses with inline ports', () => {
    const env = {
      AUNSORM_BASE_URL: '::ffff:127.0.0.1:4100/custom',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: '::ffff:127.0.0.1:4100/custom',
      origin: 'http://[::ffff:7f00:1]:4100',
      path: '/custom',
      source: {
        kind: 'direct',
        key: 'AUNSORM_BASE_URL',
      },
    });
  });

  it('returns production defaults when nothing is set but NODE_ENV=production', () => {
    const env = {
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'https://aunsorm.dev/aunsorm',
      origin: 'https://aunsorm.dev',
      path: '/aunsorm',
      source: {
        kind: 'default',
        nodeEnv: 'production',
      },
    });
  });

  it('reports normalised dot-segment paths for domain overrides', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev',
      AUNSORM_BASE_PATH: './bridge/../v1/./next/',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'https://gateway.aunsorm.dev/v1/next/',
      origin: 'https://gateway.aunsorm.dev',
      path: '/v1/next/',
      source: {
        kind: 'domain-path',
        domainKey: 'AUNSORM_BASE_DOMAIN',
        pathKey: 'AUNSORM_BASE_PATH',
      },
    });
  });

  it('strips path fragments from domain overrides when deriving the origin', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev/custom/api?preview=true',
      AUNSORM_BASE_PATH: '/bridge',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrlDetails(env)).toEqual({
      baseUrl: 'https://gateway.aunsorm.dev/bridge',
      origin: 'https://gateway.aunsorm.dev',
      path: '/bridge',
      source: {
        kind: 'domain-path',
        domainKey: 'AUNSORM_BASE_DOMAIN',
        pathKey: 'AUNSORM_BASE_PATH',
      },
    });
  });
});

describe('resolveAunsormBaseUrlDiagnostics', () => {
  it('returns diagnostics without warnings when a single override is used', () => {
    const env = {
      AUNSORM_BASE_URL: 'https://example.invalid/custom',
    } satisfies NodeJS.ProcessEnv;

    const diagnostics = resolveAunsormBaseUrlDiagnostics(env);
    expect(diagnostics.baseUrl).toBe('https://example.invalid/custom');
    expect(diagnostics.origin).toBe('https://example.invalid');
    expect(diagnostics.path).toBe('/custom');
    expect(diagnostics.warnings).toEqual([]);
  });

  it('warns when domain/path overrides are ignored in favour of direct overrides', () => {
    const env = {
      AUNSORM_BASE_URL: 'https://example.invalid/custom',
      AUNSORM_BASE_DOMAIN: 'api.aunsorm.dev',
      AUNSORM_BASE_PATH: 'bridge',
    } satisfies NodeJS.ProcessEnv;

    const diagnostics = resolveAunsormBaseUrlDiagnostics(env);
    expect(diagnostics.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          message:
            'Ignored domain/path base URL environment variables because a direct base URL override is configured.',
          keys: expect.arrayContaining(['AUNSORM_BASE_DOMAIN', 'AUNSORM_BASE_PATH']),
        }),
      ]),
    );
  });

  it('warns when file-based overrides shadow direct values', () => {
    const env = {
      AUNSORM_BASE_URL_FILE: '/secrets/base-url',
      AUNSORM_BASE_URL: 'https://ignored.invalid/should-not-apply',
      AUNSORM_BASE_DOMAIN: 'api.aunsorm.dev',
    } satisfies NodeJS.ProcessEnv;

    const readStub = vi.fn(() => 'https://file.example.invalid/custom');
    const diagnostics = resolveAunsormBaseUrlDiagnostics(env, readStub);

    expect(diagnostics.baseUrl).toBe('https://file.example.invalid/custom');
    expect(diagnostics.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          message:
            'Ignored direct base URL environment variables because a base URL file override is configured.',
          keys: ['AUNSORM_BASE_URL'],
        }),
        expect.objectContaining({
          message:
            'Ignored domain/path base URL environment variables because a base URL file override is configured.',
          keys: ['AUNSORM_BASE_DOMAIN'],
        }),
      ]),
    );
  });

  it('warns about conflicting domain overrides', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'api.aunsorm.dev',
      VERCEL_URL: 'preview-aunsorm.vercel.app',
    } satisfies NodeJS.ProcessEnv;

    const diagnostics = resolveAunsormBaseUrlDiagnostics(env);

    expect(diagnostics.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          message:
            'Conflicting domain override environment variables detected; ensure only one is set.',
          keys: ['AUNSORM_BASE_DOMAIN', 'VERCEL_URL'],
        }),
      ]),
    );
  });

  it('warns when production deployments rely on insecure direct overrides', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_URL: 'http://api.aunsorm.dev/custom',
    } satisfies NodeJS.ProcessEnv;

    const diagnostics = resolveAunsormBaseUrlDiagnostics(env);

    expect(diagnostics.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          message:
            'In production environments HTTPS must be used for non-loopback hosts; current base URL resolves to http://.',
          keys: ['AUNSORM_BASE_URL'],
        }),
      ]),
    );
  });

  it('warns when domain overrides include path or query components', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev/custom',
      NEXT_PUBLIC_AUNSORM_BASE_DOMAIN: 'https://alt.aunsorm.dev/other?preview=true',
    } satisfies NodeJS.ProcessEnv;

    const diagnostics = resolveAunsormBaseUrlDiagnostics(env);

    expect(diagnostics.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          message: expect.stringContaining('Domain override values should not include URL paths'),
          keys: ['AUNSORM_BASE_DOMAIN', 'NEXT_PUBLIC_AUNSORM_BASE_DOMAIN'],
        }),
      ]),
    );
  });

  it('does not warn about http overrides for loopback hosts', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_URL: 'http://127.0.0.1:4100/custom',
    } satisfies NodeJS.ProcessEnv;

    const diagnostics = resolveAunsormBaseUrlDiagnostics(env);

    expect(diagnostics.warnings).toEqual(
      expect.not.arrayContaining([
        expect.objectContaining({
          message:
            'In production environments HTTPS must be used for non-loopback hosts; current base URL resolves to http://.',
        }),
      ]),
    );
  });
});
