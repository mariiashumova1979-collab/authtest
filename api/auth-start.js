import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const CLIENT_ID = process.env.CLIENT_ID || '8621756325';
  const REDIRECT_URI = process.env.REDIRECT_URI;

  // Генерируем PKCE
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // State для CSRF защиты
  const state = crypto.randomBytes(16).toString('hex');

  // Сохраняем в глобальное хранилище (в продакшене — Redis/DB)
  const sessions = globalThis._sessions || (globalThis._sessions = new Map());
  sessions.set(state, {
    codeVerifier,
    createdAt: Date.now()
  });

  // Чистим старые сессии (>5 мин)
  for (const [k, v] of sessions) {
    if (Date.now() - v.createdAt > 300000) sessions.delete(k);
  }

  const authUrl = `https://oauth.telegram.org/auth?` +
    `client_id=${CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}&` +
    `response_type=code&` +
    `scope=openid+profile+phone&` +
    `state=${state}&` +
    `code_challenge=${codeChallenge}&` +
    `code_challenge_method=S256`;

  // Редиректим пользователя на Telegram OAuth
  res.redirect(302, authUrl);
}
