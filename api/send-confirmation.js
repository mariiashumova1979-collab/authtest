// Хранилище сессий (в памяти — для прототипа достаточно)
// В продакшене использовать Redis или базу данных
const sessions = globalThis._sessions || (globalThis._sessions = new Map());

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });

  // Нормализуем номер
  const normalized = '+' + phone.replace(/\D/g, '').replace(/^8/, '7');

  // База разрешённых номеров → Telegram chat_id
  // ЗАПОЛНИ СВОИМИ ДАННЫМИ в переменных окружения:
  // ALLOWED_PHONES = "+79991234567:123456789,+79997654321:987654321"
  // формат: номер:telegram_chat_id через запятую
  const allowedRaw = process.env.ALLOWED_PHONES || '';
  const allowedMap = {};
  allowedRaw.split(',').forEach(pair => {
    const [p, chatId] = pair.trim().split(':');
    if (p && chatId) allowedMap[p] = chatId;
  });

  if (!allowedMap[normalized]) {
    return res.status(404).json({ error: 'phone_not_found' });
  }

  const chatId = allowedMap[normalized];
  const sessionId = Math.random().toString(36).slice(2) + Date.now().toString(36);

  // Сохраняем сессию
  sessions.set(sessionId, {
    phone: normalized,
    chatId,
    confirmed: false,
    createdAt: Date.now()
  });

  // Отправляем сообщение в Telegram с inline-кнопкой
  const BOT_TOKEN = process.env.BOT_TOKEN;
  const tgRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text: '🔐 Запрос на вход в аккаунт\n\nКто-то пытается войти с номером ' + normalized + '.\n\nЕсли это вы — нажмите кнопку ниже.',
      reply_markup: {
        inline_keyboard: [[
          { text: '✅ Подтвердить вход', callback_data: 'confirm_' + sessionId }
        ], [
          { text: '❌ Это не я', callback_data: 'deny_' + sessionId }
        ]]
      }
    })
  });

  if (!tgRes.ok) {
    const err = await tgRes.text();
    console.error('Telegram error:', err);
    return res.status(500).json({ error: 'telegram_error' });
  }

  return res.status(200).json({ session_id: sessionId });
}
