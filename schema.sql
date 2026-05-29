-- ═══════════════════════════════════════════════
-- FINTREK — Schema Supabase PostgreSQL (v2 seguro)
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

ALTER TABLE ft_users DISABLE ROW LEVEL SECURITY;


-- ── Sessões (tokens com expiração de 30 dias) ───
CREATE TABLE ft_sessions (
  id         BIGSERIAL    PRIMARY KEY,
  token      TEXT         UNIQUE NOT NULL,
  user_id    BIGINT       NOT NULL REFERENCES ft_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ  NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

ALTER TABLE ft_sessions DISABLE ROW LEVEL SECURITY;

CREATE INDEX idx_ft_sessions_token      ON ft_sessions(token);
CREATE INDEX idx_ft_sessions_expires_at ON ft_sessions(expires_at);


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


-- ── Limpeza automática de sessões expiradas ──────
-- Cria um job via pg_cron (disponível no Supabase):
-- SELECT cron.schedule('limpar-sessoes', '0 3 * * *',
--   $$DELETE FROM ft_sessions WHERE expires_at < NOW()$$);