import { describe, expect, it } from 'vitest';

import { resolveAunsormBaseUrl } from './experimental-integrations.js';

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

  it('removes trailing slash when the path override is empty', () => {
    const env = {
      NODE_ENV: 'production',
      AUNSORM_BASE_DOMAIN: 'gateway.aunsorm.dev/',
      AUNSORM_BASE_PATH: '',
    } satisfies NodeJS.ProcessEnv;

    expect(resolveAunsormBaseUrl(env)).toBe('https://gateway.aunsorm.dev');
  });
});
