-- Refresh tokens opacos. Só o SHA-256 do token é gravado.
-- family_id agrupa os tokens nascidos do mesmo login: reusar um token já
-- trocado (used_at preenchido) revoga a família inteira.
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id   UUID        NOT NULL,
    token_hash  BYTEA       NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at     TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    replaced_by UUID REFERENCES refresh_tokens (id),
    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
