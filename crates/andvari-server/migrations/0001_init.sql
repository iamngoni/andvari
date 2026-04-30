-- Andvari initial schema.
--
-- All UUIDs are server-generated via Postgres' built-in `gen_random_uuid()`
-- (Postgres 13+); no extensions required.
--
-- Encryption: ciphertext columns hold the wire bytes of `SecretEnvelope`
-- (see `andvari-core::crypto::SecretEnvelope::to_bytes`). Plaintext NEVER
-- lands in any column.

-- ---------------------------------------------------------------------------
-- Workspaces and identity
-- ---------------------------------------------------------------------------

-- Top-level isolation boundary. Each workspace has its own KEK, wrapped under
-- the Root Key.
CREATE TABLE workspaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    kek_wrapped     BYTEA NOT NULL,
    kek_nonce       BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Identities — populated on first OIDC login; we never store passwords.
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_issuer     TEXT NOT NULL,
    oidc_subject    TEXT NOT NULL,
    email           TEXT,
    display_name    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ,
    UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE memberships (
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            TEXT NOT NULL
                    CHECK (role IN ('owner','admin','writer','reader','auditor')),
    granted_by      UUID REFERENCES users(id),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Hierarchy: project → environment → secret → secret_version
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, slug)
);

CREATE TABLE environments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    requires_approval   BOOLEAN NOT NULL DEFAULT FALSE,
    approver_count      INT NOT NULL DEFAULT 1 CHECK (approver_count >= 1),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

-- A named secret in a specific environment. `current_version_id` is set after
-- the first version is created; older versions remain immutable for history
-- and rollback.
CREATE TABLE secrets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id      UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    key                 TEXT NOT NULL,
    current_version_id  UUID,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (environment_id, key)
);

CREATE TABLE secret_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    -- Wire bytes of SecretEnvelope: includes wrapped DEK, nonces, AEAD tag.
    ciphertext      BYTEA NOT NULL,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Set the FK on `secrets.current_version_id` only after `secret_versions`
-- exists (the two reference each other).
ALTER TABLE secrets
    ADD CONSTRAINT secrets_current_version_fk
    FOREIGN KEY (current_version_id) REFERENCES secret_versions(id);

CREATE INDEX secret_versions_secret_id_created_at_idx
    ON secret_versions(secret_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Auth: service tokens, OIDC trust, web sessions
-- ---------------------------------------------------------------------------

CREATE TABLE service_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    -- Indexed prefix for O(1) lookup; hash for verification (Argon2id).
    token_prefix    TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    scopes          JSONB NOT NULL,
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX service_tokens_prefix_idx ON service_tokens(token_prefix);
CREATE INDEX service_tokens_workspace_idx ON service_tokens(workspace_id);

-- Allow CI systems / external IdPs to exchange OIDC tokens for short-lived
-- Andvari tokens.
CREATE TABLE oidc_trust (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    issuer          TEXT NOT NULL,
    audience        TEXT NOT NULL,
    -- e.g. `repo:iamngoni/spirit-finder:ref:refs/heads/main`
    subject_pattern TEXT NOT NULL,
    role            TEXT NOT NULL,
    ttl_seconds     INT NOT NULL DEFAULT 900 CHECK (ttl_seconds > 0)
);

CREATE INDEX oidc_trust_workspace_issuer_idx ON oidc_trust(workspace_id, issuer);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ NOT NULL,
    csrf_token      TEXT NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sessions_expires_idx ON sessions(expires_at);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------

-- Every read, write, token mint, membership change, etc. lands here.
-- `hmac_chain` chains rows together so any retroactive edit breaks
-- verification at the tampered row and forwards.
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    workspace_id    UUID,
    actor_id        UUID,
    actor_kind      TEXT NOT NULL
                    CHECK (actor_kind IN ('user','token','oidc-fed','system')),
    action          TEXT NOT NULL,
    target_kind     TEXT,
    target_id       UUID,
    ip              INET,
    user_agent      TEXT,
    request_id      UUID,
    -- HMAC-SHA256(prev_chain || canonical_bytes_of_this_row), keyed from RK.
    hmac_chain      BYTEA NOT NULL
);

CREATE INDEX audit_log_workspace_ts_idx ON audit_log(workspace_id, ts DESC);
CREATE INDEX audit_log_action_idx ON audit_log(action);

-- ---------------------------------------------------------------------------
-- Dynamic secrets — short-lived credentials minted on demand.
-- ---------------------------------------------------------------------------

CREATE TABLE leases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    -- e.g. 'postgres', 'mysql', 'aws-sts', 'ssh-otp'
    engine          TEXT NOT NULL,
    -- Engine-specific identifier (DB role name, IAM role ARN, hostname, …).
    scope           TEXT NOT NULL,
    params          JSONB NOT NULL DEFAULT '{}'::jsonb,
    issued_to       UUID REFERENCES users(id),
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX leases_active_expires_idx
    ON leases(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX leases_workspace_engine_idx
    ON leases(workspace_id, engine);

-- ---------------------------------------------------------------------------
-- Approvals — for `requires_approval = true` environments and other
-- privileged operations.
-- ---------------------------------------------------------------------------

CREATE TABLE approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    requested_by    UUID NOT NULL REFERENCES users(id),
    -- e.g. 'secret.write', 'membership.grant', 'engine.configure'.
    action          TEXT NOT NULL,
    target          JSONB NOT NULL,
    required_count  INT NOT NULL DEFAULT 1 CHECK (required_count >= 1),
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','rejected','executed','expired')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    executed_at     TIMESTAMPTZ
);

CREATE INDEX approvals_workspace_status_idx ON approvals(workspace_id, status);

CREATE TABLE approval_signoffs (
    approval_id     UUID NOT NULL REFERENCES approvals(id) ON DELETE CASCADE,
    approver_id     UUID NOT NULL REFERENCES users(id),
    approved_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (approval_id, approver_id)
);

-- App-side check: requesters MUST NOT self-approve. We do not enforce this
-- via a trigger to keep operational complexity low; the constraint lives in
-- the approval handler.

-- ---------------------------------------------------------------------------
-- Webhooks
-- ---------------------------------------------------------------------------

CREATE TABLE webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    -- Array of event names this webhook subscribes to.
    events          JSONB NOT NULL,
    -- HMAC-SHA256 key used to sign delivery payloads.
    secret          BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at     TIMESTAMPTZ
);

CREATE INDEX webhooks_workspace_idx ON webhooks(workspace_id) WHERE disabled_at IS NULL;

CREATE TABLE webhook_deliveries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id          UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type          TEXT NOT NULL,
    payload             JSONB NOT NULL,
    attempt             INT NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','success','failure','dead-letter')),
    last_attempted_at   TIMESTAMPTZ,
    next_attempt_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    succeeded_at        TIMESTAMPTZ,
    response_status     INT,
    response_body       TEXT
);

CREATE INDEX webhook_deliveries_pending_idx
    ON webhook_deliveries(next_attempt_at) WHERE status = 'pending';
