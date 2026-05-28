// api/auth.js — Login e Cadastro
const { Pool } = require('pg');
const crypto   = require('crypto');

const pool = new Pool({ connectionString: process.env.POSTGRES_URL, ssl: { rejectUnauthorized: false } });

function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + 'fintrek_salt_2025').digest('hex');
}

function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = async (req, res) => {
  // Permite chamadas do seu site
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, err: 'Método não permitido' });

  const { action, nome, email, pass } = req.body;

  if (!email || !pass) return res.json({ ok: false, err: 'Email e senha obrigatórios.' });

  const client = await pool.connect();
  try {
    // ── CADASTRO ──
    if (action === 'register') {
      if (!nome) return res.json({ ok: false, err: 'Nome obrigatório.' });
      if (pass.length < 6) return res.json({ ok: false, err: 'Senha deve ter pelo menos 6 caracteres.' });

      const exists = await client.query('SELECT id FROM ft_users WHERE email = $1', [email]);
      if (exists.rows.length > 0) return res.json({ ok: false, err: 'Este email já está cadastrado.' });

      const result = await client.query(
        'INSERT INTO ft_users (nome, email, pass_hash) VALUES ($1, $2, $3) RETURNING id, nome, email',
        [nome, email, hashPass(pass)]
      );
      const user  = result.rows[0];
      const token = makeToken();
      await client.query('INSERT INTO ft_sessions (token, user_id) VALUES ($1, $2)', [token, user.id]);
      return res.json({ ok: true, user, token });
    }

    // ── LOGIN ──
    if (action === 'login') {
      const result = await client.query('SELECT * FROM ft_users WHERE email = $1', [email]);
      if (!result.rows.length) return res.json({ ok: false, err: 'Email não encontrado.' });

      const user = result.rows[0];
      if (user.pass_hash !== hashPass(pass)) return res.json({ ok: false, err: 'Senha incorreta.' });

      const token = makeToken();
      await client.query('INSERT INTO ft_sessions (token, user_id) VALUES ($1, $2)', [token, user.id]);
      return res.json({ ok: true, user: { id: user.id, nome: user.nome, email: user.email }, token });
    }

    return res.json({ ok: false, err: 'Ação inválida.' });

  } catch (err) {
    console.error('Auth error:', err);
    return res.status(500).json({ ok: false, err: 'Erro interno do servidor.' });
  } finally {
    client.release();
  }
  module.exports = async function handler(req, res){

  if(req.method !== 'POST'){
    return res.status(405).json({
      error:'Método não permitido'
    });
  }

  const { email, senha } = req.body;

  // LOGIN AQUI

  return res.status(200).json({
    success:true,
    token:'123'
  });
}
};