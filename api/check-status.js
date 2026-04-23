const sessions = globalThis._sessions || (globalThis._sessions = new Map());

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'session_id required' });

  const session = sessions.get(session_id);
  if (!session) return res.status(404).json({ status: 'not_found' });

  // Проверяем не истекла ли сессия (2 минуты)
  if (Date.now() - session.createdAt > 120000) {
    sessions.delete(session_id);
    return res.status(200).json({ status: 'expired' });
  }

  if (session.denied) {
    sessions.delete(session_id);
    return res.status(200).json({ status: 'denied' });
  }

  if (session.confirmed) {
    const data = {
      status: 'confirmed',
      phone: session.phone,
      name: session.name || null
    };
    sessions.delete(session_id);
    return res.status(200).json(data);
  }

  return res.status(200).json({ status: 'pending' });
}
