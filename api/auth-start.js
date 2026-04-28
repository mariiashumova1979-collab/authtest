import crypto from 'crypto';

const DEFAULT_CLIENT_ID = '8350918144';
const DEFAULT_REDIRECT_URI = 'https://authtest-8pya.vercel.app/api/auth-callback';
const DEFAULT_SCOPES = 'openid profile phone';
const COOKIE_NAME = 'tg_oidc_session';

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function sign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function createSignedCookieValue(payload, secret) {
  const value = base64url(JSON.stringify(payload));
  return `${value}.${sign(value, secret)}`;
}

function getRequiredEnv(name, fallback = '') {
  const value = process.env[name] || fallback;
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).send('Method Not Allowed');
  }

  try {
    const CLIENT_ID = getRequiredEnv('CLIENT_ID', DEFAULT_CLIENT_ID);
    const REDIRECT_URI = getRequiredEnv('REDIRECT_URI', DEFAULT_REDIRECT_URI);
    const COOKIE_SECRET = getRequiredEnv('COOKIE_SECRET', process.env.CLIENT_SECRET || 'demo-cookie-secret-change-me');
    const SCOPES = process.env.TELEGRAM_SCOPES || DEFAULT_SCOPES;

    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    const state = crypto.randomBytes(24).toString('base64url');
    const nonce = crypto.randomBytes(24).toString('base64url');

    const cookieValue = createSignedCookieValue({
      state,
      nonce,
      codeVerifier,
      createdAt: Date.now()
    }, COOKIE_SECRET);

    res.setHeader(
      'Set-Cookie',
      `${COOKIE_NAME}=${cookieValue}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
    );

    const authUrl = new URL('https://oauth.telegram.org/auth');
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', SCOPES);
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    return res.redirect(302, authUrl.toString());
  } catch (err) {
    console.error('auth-start error:', err);
    return res.status(500).send(err.message || 'Auth start failed');
  }
}
