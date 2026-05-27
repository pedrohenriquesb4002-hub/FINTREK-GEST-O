// api/data.js — Leitura e escrita de dados por usuário
import { neon } from '@neondatabase/serverless';
import { verifyToken } from './auth.js';

function getToken(req) {
  const auth = req.headers['authorization'] || '';
  return auth.replace(/^Bearer\s+/i, '').trim();
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const userId = verifyToken(getToken(req));
  if (!userId) return res.status(401).json({ ok: false, err: 'Não autorizado.' });

  const sql = neon(process.env.DATABASE_URL);

  // ── GET /api/data — carrega todos os dados do usuário ──
  if (req.method === 'GET') {
    const rows = await sql`SELECT key, value FROM user_data WHERE user_id = ${userId}`;
    const data = {};
    rows.forEach(r => { data[r.key] = r.value; });
    return res.json({ ok: true, data });
  }

  // ── POST /api/data — salva uma chave ──────────────────
  if (req.method === 'POST') {
    const { key, value } = req.body || {};
    if (!key) return res.json({ ok: false, err: 'key obrigatório.' });

    await sql`
      INSERT INTO user_data (user_id, key, value, updated_at)
      VALUES (${userId}, ${key}, ${JSON.stringify(value)}, NOW())
      ON CONFLICT (user_id, key)
      DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
    `;
    return res.json({ ok: true });
  }

  // ── DELETE /api/data?key=xxx — remove uma chave ───────
  if (req.method === 'DELETE') {
    const key = (req.query?.key) || new URL(req.url, 'http://x').searchParams.get('key');
    if (!key) return res.json({ ok: false, err: 'key obrigatório.' });

    await sql`DELETE FROM user_data WHERE user_id = ${userId} AND key = ${key}`;
    return res.json({ ok: true });
  }

  return res.status(405).json({ ok: false, err: 'Method not allowed' });
}
