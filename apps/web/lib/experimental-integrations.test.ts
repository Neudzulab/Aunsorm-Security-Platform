import { describe, expect, it, vi } from 'vitest';

import {
  resolveAunsormBaseUrl,
  resolveAunsormBaseUrlDetails,
} from './experimental-integrations.js';

describe('resolveAunsormBaseUrl', () => {
  it('returns direct base url when an explicit variable is provided', () => {
    const env = {
      NEXT_PUBLIC_AUNSORM_BASE_URL: 'https://example.invalid/custom',
      NODE_ENV: 'production',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://example.invalid/custom');
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
});
