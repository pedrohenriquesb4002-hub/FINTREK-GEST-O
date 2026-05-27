// api/auth.js — Login e cadastro de usuários
import { neon } from '@neondatabase/serverless';
import crypto from 'crypto';

// ── helpers ──────────────────────────────────────────────

function hashPassword(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pass, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(pass, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const attempt = crypto.scryptSync(pass, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(hash, 'hex'));
  } catch { return false; }
}

export function makeToken(userId) {
  const payload = `${userId}:${Date.now()}`;
  const b64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.TOKEN_SECRET).update(b64).digest('hex');
  return `${b64}.${sig}`;
}

export function verifyToken(token) {
  try {
    const [b64, sig] = (token || '').split('.');
    const expected = crypto.createHmac('sha256', process.env.TOKEN_SECRET).update(b64).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
    const [userId] = Buffer.from(b64, 'base64url').toString().split(':');
    return userId || null;
  } catch { return null; }
}

// ── handler ──────────────────────────────────────────────

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, err: 'Method not allowed' });

  const sql = neon(process.env.DATABASE_URL);
  const { action, email, pass, nome } = req.body || {};

  // ── LOGIN ─────────────────────────────────────────────
  if (action === 'login') {
    if (!email || !pass) return res.json({ ok: false, err: 'Preencha email e senha.' });

    const rows = await sql`SELECT * FROM users WHERE email = ${email.toLowerCase().trim()}`;
    if (!rows.length) return res.json({ ok: false, err: 'Email não encontrado.' });

    const user = rows[0];
    if (!verifyPassword(pass, user.password_hash))
      return res.json({ ok: false, err: 'Senha incorreta.' });

    const token = makeToken(user.id);
    return res.json({ ok: true, token, user: { id: user.id, nome: user.nome, email: user.email } });
  }

  // ── CADASTRO ──────────────────────────────────────────
  if (action === 'register') {
    if (!nome || !email || !pass)
      return res.json({ ok: false, err: 'Preencha todos os campos.' });
    if (pass.length < 6)
      return res.json({ ok: false, err: 'Senha precisa ter no mínimo 6 caracteres.' });

    const normalEmail = email.toLowerCase().trim();
    const exists = await sql`SELECT id FROM users WHERE email = ${normalEmail}`;
    if (exists.length) return res.json({ ok: false, err: 'Este email já está cadastrado.' });

    const id = 'u_' + crypto.randomBytes(8).toString('hex');
    const password_hash = hashPassword(pass);
    await sql`INSERT INTO users (id, nome, email, password_hash) VALUES (${id}, ${nome.trim()}, ${normalEmail}, ${password_hash})`;

    const token = makeToken(id);
    return res.json({ ok: true, token, user: { id, nome: nome.trim(), email: normalEmail } });
  }

  return res.json({ ok: false, err: 'Ação inválida.' });
}
