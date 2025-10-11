import { describe, expect, it } from 'vitest';

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
