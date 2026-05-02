# Pocket ID OIDC

[Pocket ID](https://pocket-id.org) is bundled in `docker-compose.yml` as the
canonical OIDC provider for Andvari's browser logins. It runs alongside
`postgres` and `andvari` on the same compose network.

## TL;DR — first-run bootstrap

```bash
docker compose up -d
```

1. Open <http://pocket-id.localhost:1411/login/setup> — the `*.localhost`
   TLD resolves automatically to 127.0.0.1 on every modern OS, so **no
   `/etc/hosts` edit is needed**. Pocket ID's setup page is reachable
   without auth as long as no admin account exists yet.
2. Register your admin account (passkey-based — Pocket ID is passwordless;
   you'll bind a hardware key, Touch ID, Windows Hello, or 1Password).
3. After registering, you'll be signed in to the Pocket ID admin UI.
4. In Pocket ID, **OIDC Clients → New client**:
   - Name: `Andvari`
   - Callback URL: `http://127.0.0.1:18080/v1/auth/oidc/callback`
   - PKCE: enabled
   - Client type: confidential (default)
5. Copy the generated **Client ID** and **Client Secret** into a `.env` file
   at the repo root:

   ```env
   ANDVARI_OIDC_CLIENT_ID=<paste>
   ANDVARI_OIDC_CLIENT_SECRET=<paste>
   # Optional — auto-add SSO users to this workspace as `reader` (or override
   # role with ANDVARI_OIDC_DEFAULT_ROLE).
   ANDVARI_OIDC_DEFAULT_WORKSPACE=acme
   ```

6. Restart andvari so it picks up the new env:

   ```bash
   docker compose up -d andvari
   ```

7. Open <http://127.0.0.1:18080/login> — the **Continue with SSO** button is
   now active. Clicking it bounces to Pocket ID, you authenticate with your
   passkey, and Pocket ID sends you back to Andvari with a session cookie.

## Why the `*.localhost` hostname?

Andvari runs in a sibling container, so it can't use `localhost:1411` to
reach Pocket ID — `localhost` inside a container is the container itself.
And the browser can't use `pocket-id:1411` (Pocket ID's docker DNS name)
because that hostname only resolves on the docker network.

We need a hostname that resolves to **the same Pocket ID instance** from
both places, or OIDC's `iss` (issuer) claim won't match between discovery
and token validation. Three options exist:

| Approach | Browser | Andvari container | Friction |
|---|---|---|---|
| `localhost:1411` | yes | no (resolves to container itself) | breaks |
| `pocket-id:1411` (docker DNS) | no (browser can't resolve) | yes | needs `/etc/hosts` |
| **`pocket-id.localhost:1411`** | yes (auto, RFC 6761) | yes via `extra_hosts: host-gateway` | **zero config** |

Compose handles the second piece — `andvari.extra_hosts` maps
`pocket-id.localhost` to the Docker host gateway, so server-side discovery
hits the published host port (`127.0.0.1:1411`) and reaches the Pocket ID
container.

## Production deployment

In real environments, replace the local-dev defaults:

| Var | Dev default | Production |
|---|---|---|
| `APP_URL` (Pocket ID) | `http://pocket-id.localhost:1411` | `https://id.example.com` |
| `ENCRYPTION_KEY` (Pocket ID) | dev placeholder | `openssl rand -base64 32` |
| `ANDVARI_OIDC_ISSUER` | `http://pocket-id.localhost:1411` | `https://id.example.com` |
| `ANDVARI_OIDC_REDIRECT_URL` | `http://127.0.0.1:18080/...` | `https://andvari.example.com/v1/auth/oidc/callback` |
| `TRUST_PROXY` (Pocket ID) | `false` | `true` (behind Traefik/Caddy) |

Pocket ID also supports SMTP for the magic-link email fallback, MaxMind
GeoIP, and a number of branding options — see
<https://pocket-id.org/docs/configuration/environment-variables>.

## CI federation (machine identities)

Browser SSO is for humans. Machines authenticate via the workload identity
flow — see `crates/andvari-server/src/oidc/federation.rs` and the GitHub
Actions composite at `.github/actions/setup-andvari/`. To trust GitHub
Actions tokens for a workspace:

```sql
INSERT INTO oidc_trust
  (workspace_id, issuer, audience, subject_pattern, role, ttl_seconds)
VALUES
  (
    '<workspace uuid>',
    'https://token.actions.githubusercontent.com',
    'andvari',
    'repo:your-org/your-repo:ref:refs/heads/main',
    'writer',
    900
  );
```

Then in your workflow:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: ./.github/actions/setup-andvari
    with:
      audience: andvari
      env: prod
  - run: andvari run -- ./deploy.sh
```
