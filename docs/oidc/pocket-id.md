# Pocket ID OIDC

Pocket ID is the canonical self-hosted human login example for Andvari.

## Pocket ID Client

- Redirect URI: `https://andvari.example.com/v1/auth/oidc/callback`
- Scopes: `openid email profile`
- Client type: confidential if Pocket ID is serving a browser login for a deployed Andvari instance

## Andvari Server

```env
ANDVARI_OIDC_ISSUER=https://id.example.com
ANDVARI_OIDC_CLIENT_ID=andvari
ANDVARI_OIDC_CLIENT_SECRET=replace-me
ANDVARI_OIDC_REDIRECT_URL=https://andvari.example.com/v1/auth/oidc/callback
ANDVARI_OIDC_DEFAULT_WORKSPACE=spirit-finder
ANDVARI_OIDC_DEFAULT_ROLE=reader
```

When `ANDVARI_OIDC_DEFAULT_WORKSPACE` is set, first login upserts the user into
that workspace with `ANDVARI_OIDC_DEFAULT_ROLE`. Existing memberships keep their
current role.

## CI Federation

For GitHub Actions, create an `oidc_trust` row with:

```sql
INSERT INTO oidc_trust
  (workspace_id, issuer, audience, subject_pattern, role, ttl_seconds)
VALUES
  (
    '<workspace uuid>',
    'https://token.actions.githubusercontent.com',
    'andvari',
    'repo:iamngoni/spirit-finder:ref:refs/heads/main',
    'writer',
    900
  );
```

Then use the local composite action:

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
