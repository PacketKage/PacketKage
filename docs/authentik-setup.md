# Authentik OIDC setup

PacketKage has no local accounts. Every user signs in through an OpenID
Connect provider - Authentik is the reference deployment - using the
Authorization-Code flow with PKCE. The browser never sees a token beyond the
short-lived authorization code; the backend exchanges it, validates the ID
token (signature via JWKS, `iss`, `aud`/`azp`, `nonce`, `exp`/`nbf`), and mints
its own server-side session cookie.

Authorization is derived **only** from the token's group claim:

| Authentik group      | PacketKage role | Can do                                          |
| -------------------- | --------------- | ----------------------------------------------- |
| `packetkage-admin`   | Admin           | Everything, including deleting captures/cases    |
| `packetkage-analyst` | Analyst         | Upload, analyze, investigate (no destructive ops)|

A user must belong to at least one of these groups or login is refused (403).
See `backend/app/auth/` for the implementation.

---

## Option 0 - First-run setup wizard (no env editing)

If PacketKage starts **without** OIDC configured it fails closed (503 on the
product API) and the UI opens a setup wizard at `/setup` automatically. Use it
to connect any OIDC provider, including an Authentik you have already created
(create the provider/application first - see steps below).

1. Open `http://<your-host>/setup`.
2. Fill in **Issuer URL**, **Client ID**, **Client secret**, **Public URL**, and
   the group names. The redirect URI is derived from the public URL when blank.
3. Click **Test connection** - the backend fetches
   `/.well-known/openid-configuration` and the JWKS without saving anything.
4. Click **Save & enable** - values are persisted to `/data/setup.json` (`0600`)
   and applied immediately (no restart).

Notes:

* **Environment wins.** Any `PACKETKAGE_OIDC_*` / `PACKETKAGE_PUBLIC_URL` /
  `PACKETKAGE_*_GROUP` variable that is set makes that field read-only in the
  wizard. Leave the variables unset to manage everything from the UI.
* **Bootstrap token.** A remote (non-loopback) caller must supply the one-time
  token, printed once in the backend logs and stored at `/data/setup-token`.
  Loopback callers are trusted without it. Override with
  `PACKETKAGE_SETUP_TOKEN`; relocate the file with `PACKETKAGE_SETUP_FILE`.
* **Reconfiguration.** Once configured, `/setup` requires an admin session
  (analysts get 403). The client secret is stored on the data volume and is
  never returned by the API.

For local development there is a stdlib-only helper that automates all of the
above against the bundled Authentik - it fills `.env` secrets, starts the
Authentik containers (never the `packetkage` one), creates the groups, the
`groups` scope mapping, the provider and the application over the Authentik API,
and writes `backend/data/setup.json` (including the `groups` scope):

```bash
python3 scripts/packetkage-setup.py                   # defaults to the Vite dev server
python3 scripts/packetkage-setup.py --public-url http://localhost:8000  # container UI
python3 scripts/packetkage-setup.py --dry-run         # preview only
python3 scripts/packetkage-setup.py --manual          # paste credentials instead
```

It is safe to re-run and does not overwrite values that are already filled in.

---

## Option A - Bundled Authentik (local evaluation)

The repository ships a Compose overlay that runs Authentik alongside
PacketKage.

### 1. Make the provider hostname resolve

The OIDC *issuer* must be byte-for-byte identical for the backend and the
browser. The backend reaches Authentik over the Compose network as `authentik`;
your browser needs the same name, so add one line to `/etc/hosts`:

```text
127.0.0.1 authentik
```

### 2. Configure `.env`

```bash
cp .env.example .env
```

Set at least:

```dotenv
PACKETKAGE_PUBLIC_URL=http://localhost:8000
PACKETKAGE_OIDC_ISSUER=http://authentik:9000/application/o/packetkage/
PACKETKAGE_OIDC_REDIRECT_URI=http://localhost:8000/api/auth/callback
AUTHENTIK_SECRET_KEY=<openssl rand -base64 36>
AUTHENTIK_POSTGRESQL__PASSWORD=<strong password>
AUTHENTIK_BOOTSTRAP_PASSWORD=<strong admin password>
```

`PACKETKAGE_OIDC_CLIENT_ID` / `PACKETKAGE_OIDC_CLIENT_SECRET` are filled in at
step 4 (after creating the provider).

### 3. Start the stack

```bash
docker compose -f docker-compose.yml -f docker-compose.authentik.yml up -d --build
```

Authentik is then at <http://authentik:9000> (from the host, thanks to the
hosts entry). Open it and log in as `akadmin` with
`AUTHENTIK_BOOTSTRAP_PASSWORD`.

### 4. Create groups, the provider, and the application

In the Authentik admin UI:

1. **Directory → Groups → Create**
   * `packetkage-admin`
   * `packetkage-analyst`
   Add your users to the appropriate group(s).

2. **Applications → Providers → Create → OAuth2/OpenID Provider**
   * Name: `packetkage`
   * Authorization flow: `default-provider-authorization-implicit-consent`
     (or the explicit-consent flow if you prefer a consent screen)
   * Client type: **Confidential**
   * Redirect URIs: `http://localhost:8000/api/auth/callback`
     (must match `PACKETKAGE_OIDC_REDIRECT_URI` exactly - scheme, host, port, path)
   * Scopes: ensure `openid`, `profile`, `email` **and `groups`** are selected.
     Authentik ships no `groups` mapping, so create one first under
     **Customization → Property Mappings → Create → Scope Mapping**:
     * Name: `OpenID 'groups'`, Scope name: `groups`
     * Expression:
       ```python
       return {"groups": [group.name for group in request.user.ak_groups.all()]}
       ```
     Without this mapping the ID token carries no group memberships and every
     login is refused with "Access denied" (403), even for `akadmin`.
   * Advanced protocol settings → **Subject mode**: *Based on the User's
     username* is fine.

3. **Applications → Applications → Create**
   * Name: `PacketKage`
   * Slug: `packetkage` (this makes the issuer
     `http://authentik:9000/application/o/packetkage/`)
   * Provider: `packetkage`

4. Open the provider and copy the **Client ID** and **Client Secret** into
   `.env`:

   ```dotenv
   PACKETKAGE_OIDC_CLIENT_ID=<client id>
   PACKETKAGE_OIDC_CLIENT_SECRET=<client secret>
   ```

### 5. Restart PacketKage

```bash
docker compose -f docker-compose.yml -f docker-compose.authentik.yml up -d
```

Open <http://localhost:8000> → you are redirected to Authentik → after login
you land back on the PacketKage dashboard.

---

## Option B - External Authentik

Point PacketKage at any Authentik instance (or another OIDC provider) that the
backend and browsers can both reach at the same URL:

```dotenv
PACKETKAGE_PUBLIC_URL=https://packetkage.example.com
PACKETKAGE_OIDC_ISSUER=https://authentik.example.com/application/o/packetkage/
PACKETKAGE_OIDC_CLIENT_ID=<client id>
PACKETKAGE_OIDC_CLIENT_SECRET=<client secret>
PACKETKAGE_OIDC_REDIRECT_URI=https://packetkage.example.com/api/auth/callback
```

Register that redirect URI on the provider, create the two groups and the
`groups` scope exactly as in Option A. Alternatively, leave the `PACKETKAGE_OIDC_*`
variables unset and enter these values in the `/setup` wizard (Option 0).

---

## Behind a reverse proxy / TLS

Terminate TLS in front of PacketKage (sample:
[`reverse-proxy/nginx.conf`](../reverse-proxy/nginx.conf)) and set:

* `PACKETKAGE_PUBLIC_URL=https://packetkage.example.com`
* `PACKETKAGE_OIDC_REDIRECT_URI=https://packetkage.example.com/api/auth/callback`

The session cookie's `Secure` flag defaults to **on** whenever either URL is
`https://`; leave `PACKETKAGE_SESSION_SECURE` unset. If you serve plain HTTP
and still need the flag, set it explicitly.

---

## Verify

```bash
# OIDC is configured (public endpoint)
curl -s http://localhost:8000/api/auth/status
# → {"configured":true,"issuer":"http://authentik:9000/application/o/packetkage/", ...}

# Protected API is closed to anonymous callers
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/api/captures   # → 401

# Login kicks off the redirect to Authentik
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  'http://localhost:8000/api/auth/login?next=/'
# → 302 http://authentik:9000/application/o/authorize/...
```

---

## Troubleshooting

| Symptom | Cause / fix |
| ------- | ----------- |
| `503 Authentication is not configured` | `PACKETKAGE_OIDC_ISSUER` is unset/empty in the running container. Restart after setting it. |
| `Invalid issuer` after Authentik login | The issuer the backend fetches differs from the token `iss`. Ensure backend and browser use the identical issuer URL (`authentik` alias + `/etc/hosts`, or a real public hostname). |
| `redirect_uri mismatch` | `PACKETKAGE_OIDC_REDIRECT_URI` must match a registered Redirect URI on the provider exactly. |
| Login succeeds but the app shows "Access denied" | Either the user is not in `packetkage-admin` / `packetkage-analyst`, or the provider is missing the `groups` scope mapping (so no `groups` claim is emitted). Add the mapping and ensure `groups` is in `PACKETKAGE_OIDC_SCOPE` (default `openid profile email groups`), then restart. |
| No Admin link / delete buttons | Working as intended for analysts - those are admin-only. |
| Cookie not stored | Serving over HTTPS without `Secure`, or the reverse proxy rewrites the Host. Check `PACKETKAGE_PUBLIC_URL` and cookie flags in DevTools. |
| `nonce` / `expired token` errors | Clock skew between hosts. Keep the containers/hosts time-synced (NTP). |
