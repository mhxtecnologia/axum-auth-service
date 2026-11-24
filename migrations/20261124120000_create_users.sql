-- Usuários. O e-mail chega já normalizado (trim + minúsculas) pela aplicação;
-- o CHECK garante isso no banco, e a unicidade simples basta.
CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_email_lowercase CHECK (email = lower(email))
);
