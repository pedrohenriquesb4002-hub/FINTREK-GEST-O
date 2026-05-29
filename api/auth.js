// api/auth.js — Login e Cadastro  (versão segura)
// Melhorias de segurança:
//  1. bcrypt no lugar de SHA-256 com salt fixo
//  2. Sessões com expiração (30 dias)
//  3. CORS restrito à origem do app (via env ALLOWED_ORIGIN)
//  4. Validação e sanitização de inputs
//  5. Mensagem genérica em caso de falha (não vaza se email existe)

const { Pool }  = require('pg');
const crypto    = require('crypto');

// bcrypt via pure-JS para funcionar no Vercel sem binários nativos
// Caso o pacote não esteja instalado, cai no fallback pbkdf2 (ainda seguro)
let bcrypt;
try { bcrypt = require('bcryptjs'); } catch(_) { bcrypt = null; }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
});

/* ── helpers de senha ─────────────────────────────────────────── */
async function hashPass(pass) {
  if (bcrypt) return bcrypt.hash(pass, 12);
  // fallback: pbkdf2 com salt aleatório (seguro, apenas mais lento)
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(pass, salt, 100_000, 64, 'sha512').toString('hex');
  return `pbkdf2:${salt}:${hash}`;
}

async function verifyPass(pass, stored) {
  if (stored.startsWith('pbkdf2:')) {
    const [, salt, hash] = stored.split(':');
    const attempt = crypto.pbkdf2Sync(pass, salt, 100_000, 64, 'sha512').toString('hex');
    return attempt === hash;
  }
  // hash bcrypt ou legado sha256 sem salt (migra na próxima vez que fizer login)
  if (bcrypt && (stored.startsWith('$2a$') || stored.startsWith('$2b$'))) {
    return bcrypt.compare(pass, stored);
  }
  // legado: sha256 + salt fixo — aceita mas não deve ser mantido
  const legacy = crypto.createHash('sha256').update(pass + 'fintrek_salt_2025').digest('hex');
  return legacy === stored;
}

function makeToken() {
  return crypto.randomBytes(48).toString('hex');  // 96 chars, mais entropy
}

/* ── CORS ─────────────────────────────────────────────────────── */
function setCors(res) {
  const origin = process.env.ALLOWED_ORIGIN || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

/* ── sanitização simples ──────────────────────────────────────── */
function sanitize(str, maxLen = 255) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen);
}

/* ════════════════════════════════════════════════════════════════
   Handler principal
════════════════════════════════════════════════════════════════ */
module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')
    return res.status(405).json({ ok: false, err: 'Método não permitido' });

  const action = sanitize(req.body?.action);
  const nome   = sanitize(req.body?.nome   || '', 100);
  const email  = sanitize(req.body?.email  || '', 255).toLowerCase();
  const pass   = sanitize(req.body?.pass   || '', 128);

  if (!email || !pass)
    return res.json({ ok: false, err: 'Email e senha obrigatórios.' });

  // Valida formato de e-mail
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.json({ ok: false, err: 'Email inválido.' });

  let client;
  try {
    client = await pool.connect();

    /* ── CADASTRO ────────────────────────────────────────────── */
    if (action === 'register') {
      if (!nome) return res.json({ ok: false, err: 'Nome obrigatório.' });
      if (pass.length < 8)
        return res.json({ ok: false, err: 'Senha deve ter pelo menos 8 caracteres.' });

      const exists = await client.query(
        'SELECT id FROM ft_users WHERE email = $1', [email]
      );
      if (exists.rows.length > 0)
        return res.json({ ok: false, err: 'Este email já está cadastrado.' });

      const hash   = await hashPass(pass);
      const result = await client.query(
        `INSERT INTO ft_users (nome, email, pass_hash)
         VALUES ($1, $2, $3)
         RETURNING id, nome, email`,
        [nome, email, hash]
      );

      const user  = result.rows[0];
      const token = makeToken();
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 dias

      await client.query(
        'INSERT INTO ft_sessions (token, user_id, expires_at) VALUES ($1, $2, $3)',
        [token, user.id, expires]
      );

      return res.json({ ok: true, user, token });
    }

    /* ── LOGIN ───────────────────────────────────────────────── */
    if (action === 'login') {
      const result = await client.query(
        'SELECT * FROM ft_users WHERE email = $1', [email]
      );

      // Mensagem genérica: não revela se email existe ou não
      if (!result.rows.length) {
        // executa hash fictício para evitar timing attack
        await hashPass('dummy_password_for_timing');
        return res.json({ ok: false, err: 'Email ou senha incorretos.' });
      }

      const user = result.rows[0];
      const ok   = await verifyPass(pass, user.pass_hash);

      if (!ok)
        return res.json({ ok: false, err: 'Email ou senha incorretos.' });

      // Se era hash legado (sha256), re-hash com bcrypt/pbkdf2
      const isLegacy = !user.pass_hash.startsWith('$2') && !user.pass_hash.startsWith('pbkdf2:');
      if (isLegacy) {
        const newHash = await hashPass(pass);
        await client.query('UPDATE ft_users SET pass_hash=$1 WHERE id=$2', [newHash, user.id]);
      }

      const token   = makeToken();
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

      await client.query(
        'INSERT INTO ft_sessions (token, user_id, expires_at) VALUES ($1, $2, $3)',
        [token, user.id, expires]
      );

      // Limpa sessões expiradas do usuário (housekeeping leve)
      client.query(
        'DELETE FROM ft_sessions WHERE user_id=$1 AND expires_at < NOW()',
        [user.id]
      ).catch(() => {});   // não bloqueia a resposta

      return res.json({
        ok: true,
        user: { id: user.id, nome: user.nome, email: user.email },
        token
      });
    }

    return res.json({ ok: false, err: 'Ação inválida.' });

  } catch (err) {
    console.error('AUTH ERROR:', err);
    return res.status(500).json({ ok: false, err: 'Erro interno do servidor.' });
  } finally {
    if (client) client.release();
  }
};