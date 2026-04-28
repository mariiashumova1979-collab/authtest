import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const jwks = jwksClient({
  jwksUri: 'https://oauth.telegram.org/.well-known/jwks.json',
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000
});

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing env ${name}`);
  return value;
}

function parseCookies(header = '') {
  return Object.fromEntries(
    header.split(';')
      .map(v => v.trim())
      .filter(Boolean)
      .map(v => {
        const i = v.indexOf('=');
        return [decodeURIComponent(v.slice(0, i)), decodeURIComponent(v.slice(i + 1))];
      })
  );
}

function sign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function readSignedCookie(cookieValue, secret) {
  if (!cookieValue || !cookieValue.includes('.')) return null;
  const [value, signature] = cookieValue.split('.');
  const expected = sign(value, secret);

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

function verifyJwt(idToken, clientId) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      getKey,
      {
        audience: clientId,
        issuer: 'https://oauth.telegram.org',
        algorithms: ['RS256']
      },
      (err, decoded) => err ? reject(err) : resolve(decoded)
    );
  });
}

function redirectWithError(res, frontendUrl, error, details = '') {
  const params = new URLSearchParams({ error });
  if (details) params.set('details', details.slice(0, 300));
  return res.redirect(302, `${frontendUrl}?${params.toString()}`);
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).send('Method Not Allowed');

  let FRONTEND_URL = process.env.FRONTEND_URL || 'https://authtest-8pya.vercel.app';

  try {
    const CLIENT_ID = requiredEnv('CLIENT_ID');
    const CLIENT_SECRET = requiredEnv('CLIENT_SECRET');
    const REDIRECT_URI = requiredEnv('REDIRECT_URI');
    const COOKIE_SECRET = requiredEnv('COOKIE_SECRET');
    FRONTEND_URL = requiredEnv('FRONTEND_URL');

    const { code, state, error, error_description } = req.query;

    if (error) {
      return redirectWithError(res, FRONTEND_URL, String(error), String(error_description || ''));
    }

    if (!code || !state) {
      return redirectWithError(res, FRONTEND_URL, 'missing_code_or_state');
    }

    const cookies = parseCookies(req.headers.cookie || '');
    const session = readSignedCookie(cookies.tg_oidc, COOKIE_SECRET);

    res.setHeader('Set-Cookie', [
      'tg_oidc=; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=0'
    ]);

    if (!session) {
      return redirectWithError(res, FRONTEND_URL, 'invalid_or_missing_session_cookie');
    }

    if (Date.now() - Number(session.createdAt || 0) > 5 * 60 * 1000) {
      return redirectWithError(res, FRONTEND_URL, 'session_expired');
    }

    if (session.state !== state) {
      return redirectWithError(res, FRONTEND_URL, 'state_mismatch');
    }

    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const tokenRes = await fetch('https://oauth.telegram.org/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${basicAuth}`
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: session.codeVerifier
      }).toString()
    });

    if (!tokenRes.ok) {
      const text = await tokenRes.text();
      console.error('Telegram token exchange error:', tokenRes.status, text);
      return redirectWithError(res, FRONTEND_URL, 'token_exchange_failed', text);
    }

    const tokenData = await tokenRes.json();
    const decoded = await verifyJwt(tokenData.id_token, CLIENT_ID);

    if (session.nonce && decoded.nonce && decoded.nonce !== session.nonce) {
      return redirectWithError(res, FRONTEND_URL, 'nonce_mismatch');
    }

    const phone = decoded.phone_number || '';
    const allowedPhones = (process.env.ALLOWED_PHONES || '')
      .split(',')
      .map(p => p.trim())
      .filter(Boolean);

    if (allowedPhones.length > 0) {
      const normalizedPhone = phone.replace(/\D/g, '');
      const isAllowed = allowedPhones.some(p => p.replace(/\D/g, '') === normalizedPhone);

      if (!isAllowed) {
        const params = new URLSearchParams({
          error: 'phone_not_allowed',
          phone
        });
        return res.redirect(302, `${FRONTEND_URL}?${params.toString()}`);
      }
    }

    const params = new URLSearchParams({
      success: '1',
      name: decoded.name || '',
      username: decoded.preferred_username || '',
      phone,
      picture: decoded.picture || '',
      tg_id: String(decoded.id || decoded.sub || '')
    });

    return res.redirect(302, `${FRONTEND_URL}?${params.toString()}`);
  } catch (err) {
    console.error('auth-callback error:', err);
    return redirectWithError(res, FRONTEND_URL, 'auth_callback_failed', err.message || String(err));
  }
}
