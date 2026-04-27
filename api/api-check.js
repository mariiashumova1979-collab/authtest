import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const jwks = jwksClient({
  jwksUri: 'https://oauth.telegram.org/.well-known/jwks.json'
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const { code, state } = req.query;
  if (!code || !state) return res.status(400).send('Missing code or state');

  const CLIENT_ID = process.env.CLIENT_ID || '8621756325';
  const CLIENT_SECRET = process.env.CLIENT_SECRET;
  const REDIRECT_URI = process.env.REDIRECT_URI;
  const FRONTEND_URL = process.env.FRONTEND_URL;

  // Проверяем state и достаём code_verifier
  const sessions = globalThis._sessions || (globalThis._sessions = new Map());
  const session = sessions.get(state);
  if (!session) return res.status(400).send('Invalid state');
  sessions.delete(state);

  const codeVerifier = session.codeVerifier;

  // Обмениваем code на токены
  const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

  const tokenRes = await fetch('https://oauth.telegram.org/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${basicAuth}`
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier
    }).toString()
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    console.error('Token exchange error:', err);
    return res.redirect(`${FRONTEND_URL}?error=token_exchange_failed`);
  }

  const tokenData = await tokenRes.json();
  const idToken = tokenData.id_token;

  // Верифицируем JWT
  try {
    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(idToken, getKey, {
        audience: CLIENT_ID,
        issuer: 'https://oauth.telegram.org'
      }, (err, decoded) => {
        if (err) reject(err);
        else resolve(decoded);
      });
    });

    console.log('Decoded token:', decoded);

    // Проверяем номер телефона в базе
    const phone = decoded.phone_number || '';
    const allowedPhones = (process.env.ALLOWED_PHONES || '').split(',').map(p => p.trim());

    // Нормализуем для сравнения
    const normalizedPhone = phone.replace(/\D/g, '');
    const isAllowed = allowedPhones.some(p => p.replace(/\D/g, '') === normalizedPhone);

    if (!isAllowed && allowedPhones.length > 0 && allowedPhones[0] !== '') {
      return res.redirect(`${FRONTEND_URL}?error=phone_not_allowed&phone=${encodeURIComponent(phone)}`);
    }

    // Успех — редиректим на фронтенд с данными
    const params = new URLSearchParams({
      success: '1',
      name: decoded.name || '',
      username: decoded.preferred_username || '',
      phone: phone,
      picture: decoded.picture || '',
      tg_id: String(decoded.id || decoded.sub || '')
    });

    return res.redirect(`${FRONTEND_URL}?${params.toString()}`);

  } catch (err) {
    console.error('JWT verification error:', err);
    return res.redirect(`${FRONTEND_URL}?error=token_invalid`);
  }
}
