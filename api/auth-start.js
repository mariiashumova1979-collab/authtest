import crypto from 'crypto';

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing env ${name}`);
  return value;
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function sign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function makeSignedCookie(payload, secret) {
  const value = base64url(JSON.stringify(payload));
  return `${value}.${sign(value, secret)}`;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).send('Method Not Allowed');

  try {
    const CLIENT_ID = requiredEnv('CLIENT_ID');
    const REDIRECT_URI = requiredEnv('REDIRECT_URI');
    const COOKIE_SECRET = requiredEnv('COOKIE_SECRET');

    const state = crypto.randomBytes(24).toString('base64url');
    const nonce = crypto.randomBytes(24).toString('base64url');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    const cookieValue = makeSignedCookie({
      state,
      nonce,
      codeVerifier,
      createdAt: Date.now()
    }, COOKIE_SECRET);

    res.setHeader('Set-Cookie', [
      `tg_oidc=${cookieValue}; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=300`
    ]);

    const authUrl = 'https://oauth.telegram.org/auth?' + new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: 'openid profile phone',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    }).toString();

    return res.redirect(302, authUrl);
  } catch (err) {
    console.error('auth-start error:', err);
    return res.status(500).send(err.message || 'auth-start failed');
  }
}
