// api/data.js — Salvar, carregar e deletar dados do usuário (versão segura)
// Melhorias:
//  1. Verifica expiração da sessão (expires_at)
//  2. Limita tamanho do value (5 MB) para evitar abuse
//  3. Sanitiza parâmetros de query
//  4. CORS restrito via env ALLOWED_ORIGIN

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
});

const MAX_VALUE_BYTES = 5 * 1024 * 1024; // 5 MB por chave

/* ── CORS ───────────────────────────────────────────────────── */
function setCors(res) {
  const origin = process.env.ALLOWED_ORIGIN || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

/* ── Valida token e retorna usuário (com verificação de expiração) */
async function getUserFromToken(client, token) {
  if (!token || token.length > 200) return null;
  const res = await client.query(
    `SELECT u.id, u.nome, u.email
     FROM ft_sessions s
     JOIN ft_users u ON u.id = s.user_id
     WHERE s.token = $1
       AND (s.expires_at IS NULL OR s.expires_at > NOW())`,
    [token]
  );
  return res.rows[0] || null;
}

/* ════════════════════════════════════════════════════════════
   Handler principal
════════════════════════════════════════════════════════════ */
module.exports = async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();

  const client = await pool.connect();
  try {
    const user = await getUserFromToken(client, token);
    if (!user)
      return res.status(401).json({ ok: false, err: 'Não autorizado. Faça login novamente.' });

    /* ── GET — carrega todos os dados do usuário ── */
    if (req.method === 'GET') {
      const result = await client.query(
        'SELECT key, value FROM ft_data WHERE user_id = $1',
        [user.id]
      );
      const data = {};
      result.rows.forEach(row => { data[row.key] = row.value; });
      return res.json({ ok: true, data });
    }

    /* ── POST — salva um par chave-valor ── */
    if (req.method === 'POST') {
      const { key, value } = req.body || {};

      if (!key || typeof key !== 'string' || key.length > 200)
        return res.json({ ok: false, err: 'Chave inválida ou muito longa.' });

      const valueStr = JSON.stringify(value);
      if (Buffer.byteLength(valueStr, 'utf8') > MAX_VALUE_BYTES)
        return res.json({ ok: false, err: 'Valor excede o tamanho máximo permitido (5 MB).' });

      await client.query(
        `INSERT INTO ft_data (user_id, key, value, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (user_id, key) DO UPDATE SET value = $3, updated_at = NOW()`,
        [user.id, key, valueStr]
      );
      return res.json({ ok: true });
    }

    /* ── DELETE — remove uma chave ── */
    if (req.method === 'DELETE') {
      const key = typeof req.query?.key === 'string' ? req.query.key.slice(0, 200) : null;
      if (!key)
        return res.json({ ok: false, err: 'Chave obrigatória.' });

      await client.query(
        'DELETE FROM ft_data WHERE user_id = $1 AND key = $2',
        [user.id, key]
      );
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