// api/data.js — Salvar, carregar e deletar dados do usuário
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.POSTGRES_URL, ssl: { rejectUnauthorized: false } });

async function getUserFromToken(client, token) {
  if (!token) return null;
  const res = await client.query(
    'SELECT u.id, u.nome, u.email FROM ft_sessions s JOIN ft_users u ON u.id = s.user_id WHERE s.token = $1',
    [token]
  );
  return res.rows[0] || null;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Extrai token do header Authorization: Bearer <token>
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();

  const client = await pool.connect();
  try {
    const user = await getUserFromToken(client, token);
    if (!user) return res.status(401).json({ ok: false, err: 'Não autorizado. Faça login novamente.' });

    // ── GET — carrega todos os dados do usuário ──
    if (req.method === 'GET') {
      const result = await client.query(
        'SELECT key, value FROM ft_data WHERE user_id = $1',
        [user.id]
      );
      const data = {};
      result.rows.forEach(row => { data[row.key] = row.value; });
      return res.json({ ok: true, data });
    }

    // ── POST — salva um par chave-valor ──
    if (req.method === 'POST') {
      const { key, value } = req.body;
      if (!key) return res.json({ ok: false, err: 'Chave obrigatória.' });

      await client.query(
        `INSERT INTO ft_data (user_id, key, value, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (user_id, key) DO UPDATE SET value = $3, updated_at = NOW()`,
        [user.id, key, JSON.stringify(value)]
      );
      return res.json({ ok: true });
    }

    // ── DELETE — remove uma chave ──
    if (req.method === 'DELETE') {
      const key = req.query.key;
      if (!key) return res.json({ ok: false, err: 'Chave obrigatória.' });

      await client.query('DELETE FROM ft_data WHERE user_id = $1 AND key = $2', [user.id, key]);
      return res.json({ ok: true });
    }

    return res.status(405).json({ ok: false, err: 'Método não permitido.' });

  } catch (err) {
    console.error('Data error:', err);
    return res.status(500).json({ ok: false, err: 'Erro interno do servidor.' });
  } finally {
    client.release();
  }
};