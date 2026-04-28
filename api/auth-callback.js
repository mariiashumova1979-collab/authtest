import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import crypto from 'crypto';

const DEFAULT_CLIENT_ID = '8350918144';
const DEFAULT_REDIRECT_URI = 'https://authtest-8pya.vercel.app/api/auth-callback';
const DEFAULT_FRONTEND_URL = 'https://authtest-8pya.vercel.app';
const COOKIE_NAME = 'tg_oidc_session';
const MAX_SESSION_AGE_MS = 10 * 60 * 1000;

const jwks = jwksClient({
  jwksUri: 'https://oauth.telegram.org/.well-known/jwks.json',
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 60 * 60 * 1000
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

function sign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || '';
  const cookies = cookieHeader.split(';').map(v => v.trim()).filter(Boolean);
  for (const cookie of cookies) {
    const index = cookie.indexOf('=');
    if (index === -1) continue;
    const key = cookie.slice(0, index);
    const value = cookie.slice(index + 1);
    if (key === name) return decodeURIComponent(value);
  }
  return '';
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  );
}

function readSignedCookie(req, secret) {
  const raw = getCookie(req, COOKIE_NAME);
  if (!raw) return null;

  const [value, signature] = raw.split('.');
  if (!value || !signature) return null;

  const expected = sign(value, secret);
  const ok = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  if (!ok) return null;

  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

function redirectWithError(res, frontendUrl, error, details = '') {
  const url = new URL(frontendUrl);
  url.searchParams.set('tg_error', error);
  if (details) url.searchParams.set('tg_error_details', details.slice(0, 300));
  return res.redirect(302, url.toString());
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).send('Method Not Allowed');
  }

  const CLIENT_ID = process.env.CLIENT_ID || DEFAULT_CLIENT_ID;
  const CLIENT_SECRET = process.env.CLIENT_SECRET;
  const REDIRECT_URI = process.env.REDIRECT_URI || DEFAULT_REDIRECT_URI;
  const FRONTEND_URL = process.env.FRONTEND_URL || DEFAULT_FRONTEND_URL;
  const COOKIE_SECRET = process.env.COOKIE_SECRET || CLIENT_SECRET || 'demo-cookie-secret-change-me';

  clearSessionCookie(res);

  try {
    if (!CLIENT_SECRET) {
      return redirectWithError(res, FRONTEND_URL, 'missing_client_secret');
    }

    const { code, state, error, error_description } = req.query;

    if (error) {
      return redirectWithError(res, FRONTEND_URL, String(error), String(error_description || ''));
    }

    if (!code || !state) {
      return redirectWithError(res, FRONTEND_URL, 'missing_code_or_state');
    }

    const session = readSignedCookie(req, COOKIE_SECRET);
    if (!session) {
      return redirectWithError(res, FRONTEND_URL, 'invalid_or_expired_session');
    }

    if (Date.now() - Number(session.createdAt || 0) > MAX_SESSION_AGE_MS) {
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
      const tokenErr = await tokenRes.text();
      console.error('Telegram token exchange error:', tokenRes.status, tokenErr);
      return redirectWithError(res, FRONTEND_URL, 'token_exchange_failed', tokenErr);
    }

    const tokenData = await tokenRes.json();
    const idToken = tokenData.id_token;

    if (!idToken) {
      return redirectWithError(res, FRONTEND_URL, 'missing_id_token');
    }

    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(
        idToken,
        getKey,
        {
          audience: CLIENT_ID,
          issuer: 'https://oauth.telegram.org',
          nonce: session.nonce
        },
        (verifyErr, verifiedToken) => {
          if (verifyErr) reject(verifyErr);
          else resolve(verifiedToken);
        }
      );
    });

    const allowedPhonesRaw = process.env.ALLOWED_PHONES || '';
    const allowedPhones = allowedPhonesRaw.split(',').map(p => p.trim()).filter(Boolean);
    const phone = decoded.phone_number || '';

    if (allowedPhones.length > 0) {
      const normalizedPhone = phone.replace(/\D/g, '');
      const isAllowed = allowedPhones.some(p => p.replace(/\D/g, '') === normalizedPhone);
      if (!isAllowed) {
        const url = new URL(FRONTEND_URL);
        url.searchParams.set('tg_error', 'phone_not_allowed');
        if (phone) url.searchParams.set('phone', phone);
        return res.redirect(302, url.toString());
      }
    }

    const url = new URL(FRONTEND_URL);
    url.searchParams.set('tg_success', '1');
    url.searchParams.set('name', decoded.name || '');
    url.searchParams.set('username', decoded.preferred_username || '');
    url.searchParams.set('phone', phone);
    url.searchParams.set('picture', decoded.picture || '');
    url.searchParams.set('tg_id', String(decoded.id || decoded.sub || ''));

    return res.redirect(302, url.toString());
  } catch (err) {
    console.error('auth-callback error:', err);
    return redirectWithError(res, FRONTEND_URL, 'callback_failed', err.message || 'Unknown error');
  }
}
