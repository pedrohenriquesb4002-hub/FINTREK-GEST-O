-- ═══════════════════════════════════════════════
-- FINTREK — Schema Neon PostgreSQL
-- Cole isso no SQL Editor do Neon e execute.
-- ═══════════════════════════════════════════════

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  nome          TEXT NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Armazenamento chave-valor por usuário
-- Espelha exatamente o padrão do localStorage:
--   ft_{entity} → value
-- mas separado por user_id
CREATE TABLE IF NOT EXISTS user_data (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key        TEXT NOT NULL,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, key)
);

CREATE INDEX IF NOT EXISTS idx_user_data_uid ON user_data(user_id);
