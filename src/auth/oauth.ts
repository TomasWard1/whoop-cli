import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import open from 'open';
import { saveTokens, clearTokens, getTokenStatus, isTokenExpired, loadTokens, refreshAccessToken } from './tokens.js';
import { getCredentials as getStoredCredentials, saveConfig } from './config.js';
import { WhoopError, ExitCode } from '../utils/errors.js';
import type { OAuthTokenResponse } from '../types/whoop.js';

const WHOOP_AUTH_URL = 'https://api.prod.whoop.com/oauth/oauth2/auth';
const WHOOP_TOKEN_URL = 'https://api.prod.whoop.com/oauth/oauth2/token';
const SCOPES = 'read:profile read:body_measurement read:workout read:recovery read:sleep read:cycles offline';

const DEFAULT_REDIRECT_URI = 'http://localhost:8787/callback';

function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function promptSecret(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stderr.write(question);
    const stdin = process.stdin;
    if (!stdin.isTTY) return resolve('');
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    let input = '';
    const onData = (data: string) => {
      for (const char of data) {
        if (char === '\n' || char === '\r') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stderr.write('\n');
          resolve(input.trim());
          return;
        } else if (char === '\u0003') {
          stdin.setRawMode(false);
          process.exit(130);
        } else if (char === '\u007f' || char === '\b') {
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stderr.write('\b \b');
          }
        } else {
          input += char;
          process.stderr.write('*');
        }
      }
    };
    stdin.on('data', onData);
  });
}

async function resolveCredentials(): Promise<{ clientId: string; clientSecret: string; redirectUri: string }> {
  const stored = getStoredCredentials();
  if (stored) return stored;

  // Interactive onboarding
  console.error('');
  console.error('  WHOOP CLI — First-time setup');
  console.error('  ────────────────────────────');
  console.error('');
  console.error('  1. Go to https://developer.whoop.com');
  console.error('  2. Create an application (apps with <10 users need no review)');
  console.error('  3. Set the Redirect URI to: ' + DEFAULT_REDIRECT_URI);
  console.error('  4. Copy your Client ID and Client Secret below');
  console.error('');
  console.error('  Everything stays local in ~/.whoop-cli/config.json');
  console.error('');

  const clientId = await prompt('  Client ID: ');
  const clientSecret = await promptSecret('  Client Secret: ');

  if (!clientId || !clientSecret) {
    throw new WhoopError('Client ID and Client Secret are required', ExitCode.AUTH_ERROR);
  }

  saveConfig({ client_id: clientId, client_secret: clientSecret, redirect_uri: DEFAULT_REDIRECT_URI });
  console.error('');
  console.error('  ✓ Credentials saved to ~/.whoop-cli/config.json');
  console.error('');

  return { clientId, clientSecret, redirectUri: DEFAULT_REDIRECT_URI };
}

export async function login(): Promise<void> {
  const { clientId, clientSecret, redirectUri } = await resolveCredentials();
  const state = randomBytes(16).toString('hex');

  const authUrl = new URL(WHOOP_AUTH_URL);
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('state', state);

  console.error('Opening browser for authorization...');
  console.error('\nIf browser does not open, visit this URL:\n');
  console.error(authUrl.toString());
  console.error('');

  await open(authUrl.toString()).catch(() => {});

  const callbackUrl = await prompt('Paste the callback URL here: ');

  const url = new URL(callbackUrl);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');

  if (!code) {
    throw new WhoopError('No authorization code in callback URL', ExitCode.AUTH_ERROR);
  }

  if (returnedState !== state) {
    throw new WhoopError('OAuth state mismatch', ExitCode.AUTH_ERROR);
  }

  const tokenResponse = await fetch(WHOOP_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
    }),
  });

  if (!tokenResponse.ok) {
    const text = await tokenResponse.text();
    throw new WhoopError(`Token exchange failed: ${text}`, ExitCode.AUTH_ERROR, tokenResponse.status);
  }

  const tokens = (await tokenResponse.json()) as OAuthTokenResponse;
  saveTokens(tokens);
  const tty = !!process.stdout.isTTY;
  if (tty) {
    console.error('\n  ✓ You\'re in! WHOOP data is now available.\n');
    console.error('  Try: whoop check');
  } else {
    console.log(JSON.stringify({ success: true, message: 'Authentication successful' }));
  }
}

export function logout(): void {
  clearTokens();
  const tty = !!process.stdout.isTTY;
  if (tty) {
    console.error('Logged out. Tokens cleared.');
  } else {
    console.log(JSON.stringify({ success: true, message: 'Logged out' }));
  }
}

export function status(): void {
  const tokenStatus = getTokenStatus();
  const tokens = loadTokens();
  const tty = !!process.stdout.isTTY;

  if (!tokenStatus.authenticated) {
    if (tty) {
      console.error('Not logged in. Run: whoop auth login');
    } else {
      console.log(JSON.stringify({ authenticated: false, message: 'Not logged in. Run: whoop-cli auth login' }));
    }
    process.exit(ExitCode.AUTH_ERROR);
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = tokenStatus.expires_at! - now;
  const needsRefresh = isTokenExpired(tokens!);

  if (tty) {
    const timeLeft = expiresIn > 0 ? `${Math.floor(expiresIn / 60)} min` : 'EXPIRED';
    const status = needsRefresh ? '⚠ Token needs refresh' : '✓ Authenticated';
    console.error(`${status} (expires in ${timeLeft})`);
  } else {
    console.log(JSON.stringify({
      authenticated: true,
      expires_at: tokenStatus.expires_at,
      expires_in_seconds: expiresIn,
      expires_in_human: expiresIn > 0 ? `${Math.floor(expiresIn / 60)} minutes` : 'EXPIRED',
      needs_refresh: needsRefresh,
    }));
  }
}

/**
 * Proactively refresh the access token.
 * Use this in cron jobs to keep tokens fresh.
 */
export async function refresh(): Promise<void> {
  const tokens = loadTokens();

  if (!tokens) {
    throw new WhoopError('Not authenticated. Run: whoop-cli auth login', ExitCode.AUTH_ERROR);
  }

  try {
    // Always force a token refresh so the keepalive cron reliably rotates the
    // single-use refresh token on every run, rather than skipping silently when
    // the access token still has time remaining.
    const newTokens = await refreshAccessToken(tokens);

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = newTokens.expires_at - now;

    console.log(JSON.stringify({
      success: true,
      message: 'Token refreshed successfully',
      expires_at: newTokens.expires_at,
      expires_in_seconds: expiresIn,
      expires_in_human: `${Math.floor(expiresIn / 60)} minutes`,
    }, null, 2));
  } catch (error) {
    if (error instanceof WhoopError && error.statusCode === 400) {
      // Stale/invalid refresh token — the rotation chain is broken. Surface a
      // clear error in the keepalive log so the operator knows manual re-auth is
      // required rather than retrying forever with the same bad token.
      console.log(JSON.stringify({
        success: false,
        error: 'refresh_token_invalid',
        message: 'Refresh token is stale or invalid. Manual re-authentication required.',
        action: 'Run: whoop auth login',
      }));
      throw new WhoopError(
        'Refresh token is stale or invalid. Run: whoop auth login to re-authenticate.',
        ExitCode.AUTH_ERROR,
        400
      );
    }
    if (error instanceof WhoopError && error.message.toLowerCase().includes('refresh')) {
      throw new WhoopError(
        'Refresh token expired. Please re-authenticate with: whoop-cli auth login',
        ExitCode.AUTH_ERROR
      );
    }
    throw error;
  }
}
