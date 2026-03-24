import { describe, it, expect, vi, beforeEach } from 'vitest';

// Hoist all mocks at top level — they persist across resetModules
vi.mock('open', () => ({ default: vi.fn(() => Promise.resolve(undefined)) }));
vi.mock('node:crypto', () => ({
  randomBytes: vi.fn(() => ({ toString: () => 'fakestatevalue123' })),
}));
vi.mock('node:readline', () => ({
  createInterface: vi.fn(() => ({
    question: vi.fn(),
    close: vi.fn(),
  })),
}));

vi.mock('../config.js', () => ({
  getCredentials: vi.fn(),
  saveConfig: vi.fn(),
}));

vi.mock('../tokens.js', () => ({
  saveTokens: vi.fn(),
  clearTokens: vi.fn(),
  loadTokens: vi.fn(),
  getTokenStatus: vi.fn(),
  getValidTokens: vi.fn(),
  isTokenExpired: vi.fn(),
  refreshAccessToken: vi.fn(),
}));

// Import after mocks are set up
import { login, logout, status, refresh } from '../oauth.js';
import { getCredentials } from '../config.js';
import { loadTokens, getTokenStatus, refreshAccessToken } from '../tokens.js';
import { createInterface } from 'node:readline';

beforeEach(() => {
  vi.clearAllMocks();
});

function mockReadline(answer: string) {
  vi.mocked(createInterface).mockReturnValue({
    question: vi.fn((_q: string, cb: (answer: string) => void) => cb(answer)),
    close: vi.fn(),
  } as any);
}

describe('login', () => {
  it('throws when no credentials and user provides empty input', async () => {
    vi.mocked(getCredentials).mockReturnValue(null);
    mockReadline('');

    await expect(login()).rejects.toThrow('Client ID and Client Secret are required');
  });

  it('throws on missing auth code in callback URL', async () => {
    vi.mocked(getCredentials).mockReturnValue({
      clientId: 'test-id',
      clientSecret: 'test-secret',
      redirectUri: 'http://localhost:8787/callback',
    });
    mockReadline('http://localhost:8787/callback?error=access_denied');

    await expect(login()).rejects.toThrow('No authorization code in callback URL');
  });

  it('throws on OAuth state mismatch', async () => {
    vi.mocked(getCredentials).mockReturnValue({
      clientId: 'test-id',
      clientSecret: 'test-secret',
      redirectUri: 'http://localhost:8787/callback',
    });
    mockReadline('http://localhost:8787/callback?code=authcode123&state=wrongstate');

    await expect(login()).rejects.toThrow('OAuth state mismatch');
  });

  it('throws when token exchange fails', async () => {
    vi.mocked(getCredentials).mockReturnValue({
      clientId: 'test-id',
      clientSecret: 'test-secret',
      redirectUri: 'http://localhost:8787/callback',
    });
    mockReadline('http://localhost:8787/callback?code=authcode123&state=fakestatevalue123');

    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: () => Promise.resolve('{"error":"invalid_grant"}'),
    });
    vi.stubGlobal('fetch', mockFetch);

    await expect(login()).rejects.toThrow('Token exchange failed');

    vi.unstubAllGlobals();
  });
});

describe('logout', () => {
  it('clears tokens without throwing', () => {
    logout();
  });
});

describe('refresh', () => {
  it('throws when not authenticated', async () => {
    vi.mocked(loadTokens).mockReturnValue(null);
    await expect(refresh()).rejects.toThrow('Not authenticated');
  });

  it('throws friendly message when refresh token is expired', async () => {
    vi.mocked(loadTokens).mockReturnValue({
      access_token: 'old',
      refresh_token: 'expired-refresh',
      expires_at: Math.floor(Date.now() / 1000) - 100,
      token_type: 'bearer',
      scope: 'offline',
    });

    const { WhoopError, ExitCode } = await import('../../utils/errors.js');
    vi.mocked(refreshAccessToken).mockRejectedValue(
      new WhoopError('Token refresh failed (401)', ExitCode.AUTH_ERROR, 401)
    );

    await expect(refresh()).rejects.toThrow('Refresh token expired');
  });

  it('throws clear re-auth message and logs JSON when refresh returns 400', async () => {
    vi.mocked(loadTokens).mockReturnValue({
      access_token: 'old',
      refresh_token: 'stale-refresh',
      expires_at: Math.floor(Date.now() / 1000) - 100,
      token_type: 'bearer',
      scope: 'offline',
    });

    const { WhoopError, ExitCode } = await import('../../utils/errors.js');
    vi.mocked(refreshAccessToken).mockRejectedValue(
      new WhoopError('invalid_grant', ExitCode.AUTH_ERROR, 400)
    );

    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await expect(refresh()).rejects.toThrow('Refresh token is stale or invalid');
    const output = JSON.parse(consoleSpy.mock.calls[0][0] as string);
    expect(output.success).toBe(false);
    expect(output.error).toBe('refresh_token_invalid');
    expect(output.action).toContain('whoop auth login');
    consoleSpy.mockRestore();
  });

  it('re-throws non-refresh errors as-is', async () => {
    vi.mocked(loadTokens).mockReturnValue({
      access_token: 'old',
      refresh_token: 'some-refresh',
      expires_at: Math.floor(Date.now() / 1000) - 100,
      token_type: 'bearer',
      scope: 'offline',
    });
    vi.mocked(refreshAccessToken).mockRejectedValue(new Error('Network error'));

    await expect(refresh()).rejects.toThrow('Network error');
  });

  it('outputs token info on successful refresh', async () => {
    vi.mocked(loadTokens).mockReturnValue({
      access_token: 'old',
      refresh_token: 'valid-refresh',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      token_type: 'bearer',
      scope: 'offline',
    });

    const futureExpiry = Math.floor(Date.now() / 1000) + 7200;
    vi.mocked(refreshAccessToken).mockResolvedValue({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      expires_at: futureExpiry,
      token_type: 'bearer',
      scope: 'offline',
    });

    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await refresh();

    expect(consoleSpy).toHaveBeenCalled();
    const output = JSON.parse(consoleSpy.mock.calls[0][0] as string);
    expect(output.success).toBe(true);
    expect(output.expires_at).toBe(futureExpiry);

    consoleSpy.mockRestore();
  });
});

describe('status', () => {
  it('exits with AUTH_ERROR when not authenticated', () => {
    vi.mocked(getTokenStatus).mockReturnValue({ authenticated: false });

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    const origIsTTY = process.stdout.isTTY;
    Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    expect(() => status()).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(2);

    Object.defineProperty(process.stdout, 'isTTY', { value: origIsTTY, configurable: true });
    consoleSpy.mockRestore();
    exitSpy.mockRestore();
  });
});
