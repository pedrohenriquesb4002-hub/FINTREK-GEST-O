-- ═══════════════════════════════════════════════
-- FINTREK — Schema Supabase PostgreSQL
-- Abra o SQL Editor no painel do Supabase,
-- cole tudo e clique em RUN.
-- ═══════════════════════════════════════════════

-- ── Limpa tabelas antigas se existirem ──────────
DROP TABLE IF EXISTS ft_data     CASCADE;
DROP TABLE IF EXISTS ft_sessions  CASCADE;
DROP TABLE IF EXISTS ft_users     CASCADE;


-- ── Usuários ────────────────────────────────────
CREATE TABLE ft_users (
  id         BIGSERIAL    PRIMARY KEY,
  nome       TEXT         NOT NULL,
  email      TEXT         UNIQUE NOT NULL,
  pass_hash  TEXT         NOT NULL,
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

-- Desabilita RLS (este app usa auth própria, não a do Supabase)
ALTER TABLE ft_users DISABLE ROW LEVEL SECURITY;


-- ── Sessões (tokens de login) ────────────────────
CREATE TABLE ft_sessions (
  id         BIGSERIAL    PRIMARY KEY,
  token      TEXT         UNIQUE NOT NULL,
  user_id    BIGINT       NOT NULL REFERENCES ft_users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

ALTER TABLE ft_sessions DISABLE ROW LEVEL SECURITY;

CREATE INDEX idx_ft_sessions_token ON ft_sessions(token);


-- ── Dados chave-valor por usuário ────────────────
CREATE TABLE ft_data (
  user_id    BIGINT       NOT NULL REFERENCES ft_users(id) ON DELETE CASCADE,
  key        TEXT         NOT NULL,
  value      JSONB        NOT NULL,
  updated_at TIMESTAMPTZ  DEFAULT NOW(),
  PRIMARY KEY (user_id, key)
);

ALTER TABLE ft_data DISABLE ROW LEVEL SECURITY;

CREATE INDEX idx_ft_data_uid ON ft_data(user_id);