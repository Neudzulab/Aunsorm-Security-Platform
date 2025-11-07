import { describe, expect, it, vi } from 'vitest';

import {
  AunsormOAuthClient,
  MemoryStore,
  computeCodeChallenge,
  generateCodeVerifier,
  generateState,
  type RandomSource,
} from './oauth-client.js';

const deterministicRandom: RandomSource = async (length) => {
  const buffer = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    buffer[index] = (index * 37 + 13) & 0xff;
  }
  return buffer;
};

describe('PKCE helpers', () => {
  it('generates a code verifier with allowed characters', async () => {
    const verifier = await generateCodeVerifier(50, deterministicRandom);
    expect(verifier).toHaveLength(50);
    expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('rejects invalid code verifier lengths', async () => {
    await expect(generateCodeVerifier(10, deterministicRandom)).rejects.toThrow(
      /code_verifier length must be between 43 and 128/,
    );
  });

  it('generates a state token using base64url alphabet', async () => {
    const state = await generateState(24, deterministicRandom);
    expect(state).toHaveLength(24);
    expect(state).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('computes the RFC 7636 S256 code challenge', async () => {
    const verifier = 'correcthorsebatterystaplepkce-verifier-000000000000000000000';
    const challenge = await computeCodeChallenge(verifier);
    expect(challenge).toBe('6dKnpSdCv5fufbqt_DUGfnybsl0ELwT8tB0jyDlLLtM');
  });
});

describe('AunsormOAuthClient', () => {
  it('performs the authorization request and stores session values', async () => {
    const store = new MemoryStore();
    const fetchStub = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const payload = JSON.parse((init?.body as string) ?? '{}');
      expect(payload).toMatchObject({
        client_id: 'demo-client',
        redirect_uri: 'https://app.example.com/callback',
        code_challenge_method: 'S256',
      });
      expect(typeof payload.code_challenge).toBe('string');
      expect(payload.code_challenge.length).toBeGreaterThan(20);
      expect(payload.state).toMatch(/^[A-Za-z0-9\-_]{32}$/);

      return new Response(
        JSON.stringify({
          code: 'auth_code_123',
          state: payload.state,
          expires_in: 600,
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        },
      );
    });

    const client = new AunsormOAuthClient({
      baseUrl: 'https://auth.example.com',
      fetchImpl: fetchStub,
      storage: store,
      randomSource: deterministicRandom,
    });

    const result = await client.beginAuthorization({
      clientId: 'demo-client',
      redirectUri: 'https://app.example.com/callback',
      scope: 'read write',
    });

    expect(result).toEqual({
      code: 'auth_code_123',
      state: expect.stringMatching(/^[A-Za-z0-9\-_]{32}$/),
      expiresIn: 600,
      codeVerifier: expect.any(String),
    });

    expect(store.getItem('aunsorm.oauth.state')).toBe(result.state);
    expect(store.getItem('aunsorm.oauth.code_verifier')).toBe(result.codeVerifier);
    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it('rejects state mismatch returned by the server', async () => {
    const store = new MemoryStore();
    const fetchStub = vi.fn(async () =>
      new Response(
        JSON.stringify({
          code: 'auth_code_456',
          state: 'tampered',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    const client = new AunsormOAuthClient({
      baseUrl: 'https://auth.example.com',
      fetchImpl: fetchStub,
      storage: store,
      randomSource: deterministicRandom,
    });

    await expect(
      client.beginAuthorization({
        clientId: 'demo-client',
        redirectUri: 'https://app.example.com/callback',
      }),
    ).rejects.toThrow(/State mismatch detected/);

    expect(store.getItem('aunsorm.oauth.state')).toBeNull();
    expect(store.getItem('aunsorm.oauth.code_verifier')).toBeNull();
  });

  it('validates callback state before exchanging the code', async () => {
    const store = new MemoryStore();
    store.setItem('aunsorm.oauth.state', 'expected-state');
    const client = new AunsormOAuthClient({
      baseUrl: 'https://auth.example.com',
      storage: store,
      randomSource: deterministicRandom,
    });

    const success = client.handleCallback('https://app.example.com/callback?code=abc&state=expected-state');
    expect(success).toEqual({ code: 'abc', state: 'expected-state' });

    expect(() =>
      client.handleCallback('https://app.example.com/callback?code=abc&state=wrong-state'),
    ).toThrow(/State mismatch/);
  });

  it('validates callback state using explicit override when storage is unavailable', () => {
    const client = new AunsormOAuthClient({
      baseUrl: 'https://auth.example.com',
      randomSource: deterministicRandom,
    });

    expect(() =>
      client.handleCallback(
        'https://app.example.com/callback?code=def&state=expected-state',
        'expected-state',
      ),
    ).not.toThrow();

    expect(() =>
      client.handleCallback(
        'https://app.example.com/callback?code=def&state=unexpected-state',
        'expected-state',
      ),
    ).toThrow(/State mismatch/);
  });

  it('rejects mismatched override when stored state is present', () => {
    const store = new MemoryStore();
    store.setItem('aunsorm.oauth.state', 'stored-state');

    const client = new AunsormOAuthClient({
      baseUrl: 'https://auth.example.com',
      storage: store,
      randomSource: deterministicRandom,
    });

    expect(() =>
      client.handleCallback(
        'https://app.example.com/callback?code=ghi&state=stored-state',
        'override',
      ),
    ).toThrow(/expectedStateOverride does not match stored state/);
  });

  it('exchanges the authorization code for a token and stores it', async () => {
    const store = new MemoryStore();
    store.setItem('aunsorm.oauth.state', 'state-123');
    store.setItem('aunsorm.oauth.code_verifier', 'verifier-xyz');

    const fetchStub = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const payload = JSON.parse((init?.body as string) ?? '{}');
      expect(payload).toMatchObject({
        grant_type: 'authorization_code',
        code: 'auth_code_789',
        code_verifier: 'verifier-xyz',
        client_id: 'demo-client',
        redirect_uri: 'https://app.example.com/callback',
      });

      return new Response(
        JSON.stringify({
          access_token: 'token-abc',
          token_type: 'Bearer',
          expires_in: 600,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const client = new AunsormOAuthClient({
      baseUrl: 'https://auth.example.com',
      fetchImpl: fetchStub,
      storage: store,
      randomSource: deterministicRandom,
    });

    const token = await client.exchangeToken({
      code: 'auth_code_789',
      clientId: 'demo-client',
      redirectUri: 'https://app.example.com/callback',
    });

    expect(token).toEqual({ access_token: 'token-abc', token_type: 'Bearer', expires_in: 600 });
    expect(store.getItem('aunsorm.oauth.access_token')).toBe('token-abc');
    expect(store.getItem('aunsorm.oauth.state')).toBeNull();
    expect(store.getItem('aunsorm.oauth.code_verifier')).toBeNull();
  });

  it('supports HTTP base URLs for loopback hosts during development', () => {
    expect(
      () =>
        new AunsormOAuthClient({
          baseUrl: 'http://localhost:5173',
          randomSource: deterministicRandom,
        }),
    ).not.toThrow();

    expect(
      () =>
        new AunsormOAuthClient({
          baseUrl: 'http://127.0.0.1:8080',
          randomSource: deterministicRandom,
        }),
    ).not.toThrow();

    expect(
      () =>
        new AunsormOAuthClient({
          baseUrl: 'http://[::1]:8443',
          randomSource: deterministicRandom,
        }),
    ).not.toThrow();

    expect(() => new AunsormOAuthClient({ baseUrl: 'http://evil.example.com' })).toThrow(
      /baseUrl must use HTTPS/,
    );
  });
});
