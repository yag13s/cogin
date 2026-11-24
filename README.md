# cogin

An OpenID Connect provider that authenticates with a **QR login card + PIN**.
It gives people without an email address or smartphone, or who can only use a shared terminal, a login about as strong as "Sign in with Google".

- Authentication is a QR card (something you have: a 256-bit secret) plus a PIN (something you know; the card locks after 3 wrong PINs).
- The administrator (the relying service) **issues, reissues and revokes** cards. Reissuing revokes the old card in the same step.
- Relying services get an ID token over **standard OIDC (authorization code + PKCE)**, so any OIDC client library in any language works.

> The login screens are in Japanese only for now.

## Overview

```
Relying service                      cogin                                  Card holder
──────────────────────────────────────────────────────────────────────────────────────────
① Admin API: POST /admin/v1/cards/issue {subject}
   ← token / cardUrl / qrPng (returned once)  ── print it and hand it over ──────▶
② Start login: /authorize?…&code_challenge  ─▶ login page
                                              scan the QR with the camera (or type it) ◀── card
                                              enter the PIN (set one on first use)    ◀── holder
   ◀── redirect_uri?code=…&state=…&iss=…
③ POST /token (code + code_verifier + client_secret)
   ← id_token (ES256, sub=subject, card_gen=generation)
④ Verify with JWKS → map subject to your own user and start your own session
```

If the card is scanned with a phone's built-in camera, `/c#cgc_…` opens. That page forwards to the client's `initiateLoginUri`, which then starts step ② (OIDC third-party initiated login). The card secret travels in the URL fragment, so it never reaches server or CDN logs.

## Integrating a service

### 1. Register a client

```bash
go run ./cmd/cogin new-client myapp
```

Give `client_secret` and `admin_key` to the relying service. They are shown only once. Put the hashes in cogin's config:

```json
{
  "issuer": "https://auth.example.com",
  "clients": [{
    "id": "myapp",
    "name": "My App",
    "redirectUris": ["https://myapp.example.com/auth/card/callback"],
    "secretHash": "…",
    "adminKeyHash": "…",
    "initiateLoginUri": "https://myapp.example.com/auth/card/start"
  }]
}
```

With an empty `secretHash` the client is public (SPA/native) and calls `/token` with PKCE only.

### 2. Issue cards (admin API)

Send `Authorization: Bearer {admin_key}`. An admin key has the form `{clientId}.{secret}` and can only touch that client's cards.

| Method | Path | Description |
|---|---|---|
| `POST` | `/admin/v1/cards/issue` | `{subject, displayName, activateWithinSeconds?, expiresInSeconds?}` → `{token, cardUrl, qrPng, card}`. Any existing card is revoked immediately (generation +1, PIN reset). |
| `POST` | `/admin/v1/cards/revoke` | `{subject}` → revokes the card (generation +1). |
| `POST` | `/admin/v1/cards/unlock` | `{subject}` → clears a wrong-PIN lock (the card stays the same). |
| `GET` | `/admin/v1/cards[?subject=]` | Lists all cards, or one card. Secrets are never included. |

**Cards sent as links.** You can send `cardUrl` as is in a chat app. The secret sits after `#`, so link-preview crawlers never receive it. Whoever opens the link first chooses the PIN, though, so set `activateWithinSeconds` (up to 30 days, e.g. 86400) when you send one. If no PIN is set by then, the card fails with `activation_expired`. Leave this out for printed cards handed over in person (they have no deadline).

**Card expiry.** With `expiresInSeconds` (up to 365 days), the card is refused with `card_expired` from that time on, even with the right PIN. This is useful for cards that should only work during an event. The ID token carries `card_exp` (unix seconds), so don't keep a session longer than that. Without it the card never expires.

`subject` is an opaque string chosen by the relying service (up to 256 bytes). It becomes the ID token's `sub` unchanged.
cogin keeps only a hash of the card secret, so a lost QR card has to be reissued.

### 3. Log users in (OIDC)

Discovery: `GET /.well-known/openid-configuration`

- `response_type=code` and `scope=openid`. **PKCE S256 is required**; `state` and `nonce` are recommended.
- The redirect carries `iss` (RFC 9207). Check that it matches your issuer.
- `/token` accepts `client_secret_basic`, `client_secret_post` and `none` (public clients).
- `prompt=none` always returns `login_required`, because a card login needs the holder's action.

ID token (ES256, valid for 5 minutes):

| Claim | Content |
|---|---|
| `sub` | The subject given at issue time |
| `aud` | Client ID |
| `nonce` | The nonce from the authorization request |
| `amr` | `["pin"]` (a QR code can be copied, so it does not claim `hwk` or `mfa`) |
| `name` | The displayName given at issue time |
| `card_gen` | Generation of the card used to log in |
| `card_exp` | Card expiry (unix seconds). Omitted for cards that don't expire |

### 4. Apply reissues and revocations to sessions immediately

cogin keeps no session after it issues a token. **Store `card_gen` in your session and compare it with the current generation in your own database on every request.** A reissue or revocation then also ends any session left open on a shared terminal, at once.
The admin API's issue and revoke calls return the new generation; save it in your database.

## Design decisions

| Topic | Decision | Reason |
|---|---|---|
| Card secret | 256-bit random value; only its SHA-256 is stored | Brute force is infeasible. The value can't be guessed, so a slow hash is unnecessary. |
| PIN | 4–8 digits. Runs, repeats, years and the most common PINs are rejected. Locks after 3 wrong tries | A stolen card's attacker tries the likely PINs first; banning those and allowing only 3 tries keeps the odds low. |
| PIN storage | `HMAC(pepper, cardId ‖ PIN)` | A PIN has too little entropy for a plain hash. The pepper lives outside the database, so a leaked table alone doesn't reveal PINs. |
| Failure count | Only wrong PINs count | An invalid token can't be tied to any card, and it can't be guessed either. |
| Concurrent attempts | The attempt limit is enforced in the conditional write itself | A burst of parallel PIN guesses still gets at most 3 tries in total. |
| Reissue | Generation +1, PIN reset | Someone may have seen the PIN together with the lost card. |
| Cards and clients | A card only works for the client that issued it | Stops a card for one service being used on another. |
| Login page | CSP (no inline scripts), `frame-ancestors 'none'`, JSON-only endpoints | Protects against clickjacking and CSRF. |
| QR scanning | Uses `BarcodeDetector` when available, otherwise the bundled jsQR | Shared PCs (Chrome/Edge on Windows, Firefox) lack `BarcodeDetector`. |

Known limitations (v1):

- No rate limiting in the application. It relies on tokens being unguessable; put API Gateway throttling or a WAF in front.
- No revocation webhook. The relying service is the one calling the admin API, so v1 doesn't need one.
- Only one key in JWKS, so no key rotation yet.
- A lock lasts until an administrator clears it. It does not expire by itself.

## Deploying to AWS

`infra/` (CDK, Go) defines `CoginStack`:

```
auth.example.com ─ Route53 A (alias) ─ API Gateway HTTP API (custom domain, ACM certificate)
                                         └ $default stage: throttling 20 rps / burst 40
                                         └ Lambda "cogin" (arm64, 256 MB, 10 s) ── DynamoDB "cogin"
                                                                               └─ SSM /cogin/*
```

| Resource | Settings | Reason |
|---|---|---|
| DynamoDB `cogin` | On-demand, TTL attribute `ttl`, PITR, deletion protection, retained on stack deletion | Losing it makes every issued card unusable |
| HTTP API | The execute-api URL is disabled; only the custom domain works | The issuer URL is part of every token, and throttling must not be bypassed |
| Throttling | 20 rps / burst 40 | A cost and abuse ceiling. The brute-force defence itself is the card secret plus the PIN lock |
| WAF | None | Its fixed cost (from $6/month) isn't worth it yet. Put one in front when needed |
| Logs | `/aws/lambda/cogin`, 30 days | |
| Hosted zone | An existing zone is referenced, not managed | |

Deployment settings come from CDK context. Pass them with `-c key=value`, or put them in `infra/cdk.context.json` (git-ignored):

```json
{
  "domainName": "auth.example.com",
  "hostedZoneId": "Z0123456789ABCDEFGHIJ",
  "hostedZoneName": "example.com"
}
```

Optional keys: `region` (default `ap-northeast-1`), `tableName` (default `cogin`) and `ssmPrefix` (default `/cogin`).

Secrets go straight into SSM, never through CDK or CloudFormation:

| Parameter | Type | Content |
|---|---|---|
| `/cogin/signing-key` | SecureString | ES256 private key (PEM) |
| `/cogin/pin-pepper` | SecureString | The PIN pepper. **Never change it once created**: changing it invalidates every PIN |
| `/cogin/config` | String | Issuer and client list (hashes only) |
| `/{clientId}/cogin-client-secret`, `/{clientId}/cogin-admin-key` | SecureString | The client secret and admin key, for the relying service's own deployment to read |

### First deployment

```bash
# 1. Generate the secrets and store them in SSM. Nothing secret is printed,
#    and existing parameters are never overwritten.
export AWS_REGION=ap-northeast-1
export ISSUER=https://auth.example.com
export CLIENT_ID=myapp CLIENT_NAME="My App"
export REDIRECT_URI=https://myapp.example.com/auth/card/callback
export INITIATE_LOGIN_URI=https://myapp.example.com/auth/card/start
./scripts/setup-ssm.sh           # dry run
./scripts/setup-ssm.sh --apply

# 2. Deploy cogin (ACM DNS validation takes a few minutes)
make cdk-diff
make cdk-deploy

# 3. Check
curl -s https://auth.example.com/.well-known/openid-configuration

# 4. Give the relying service's deployment the issuer, client ID and read
#    access to /{clientId}/cogin-*, then enable card login in its UI last,
#    so users never see a button that doesn't work yet.
```

After that, `make cdk-deploy` is enough. Changes to `/cogin/config` are picked up when Lambda cold-starts. To apply them at once, update the function's configuration or redeploy.

## Development

```bash
go test ./...                                                   # unit + HTTP integration tests
COGIN_TEST_DYNAMODB_ENDPOINT=http://localhost:8000 go test ./store/dynamostore/   # contract tests on DynamoDB Local

cp cogin.example.json cogin.json                                # then fill in the hashes from `cogin new-client`
COGIN_DEV=1 COGIN_CONFIG=cogin.json go run ./cmd/cogin          # in-memory store and a throwaway key (:8090)
```

DynamoDB Local can be started with `docker run --rm -p 8000:8000 amazon/dynamodb-local`.

### Environment variables

| Variable | Description |
|---|---|
| `COGIN_CONFIG` / `COGIN_CONFIG_JSON` | Path to the config file / the config JSON itself |
| `COGIN_ISSUER` | Overrides the issuer |
| `COGIN_SIGNING_KEY` / `COGIN_SIGNING_KEY_FILE` | ES256 private key (PEM). Generate one with `cogin gen-key` |
| `COGIN_PIN_PEPPER` | 32+ random bytes, base64. Generate one with `cogin gen-pepper` |
| `COGIN_STORE` | `dynamodb` (production) or `memory` (only with `COGIN_DEV=1`) |
| `COGIN_TABLE` / `DYNAMODB_ENDPOINT` | DynamoDB table name (default `cogin`; keys `PK`/`SK`, TTL attribute `ttl`) / endpoint |
| `COGIN_ADDR` | Listen address (default `:8090`) |
| `COGIN_DEV` | `1` allows a missing key or pepper and the in-memory store (development only) |

`COGIN_CONFIG_JSON`, `COGIN_SIGNING_KEY` and `COGIN_PIN_PEPPER` can also be read from SSM by setting `{NAME}_SSM_PATH` instead.

### Packages

| Package | Role |
|---|---|
| `card` | Core logic (issue, reissue, revoke, PIN, lock). Depends on neither HTTP nor storage |
| `oidc` | Client registry, authorization request validation, PKCE, authorization codes, ID token signing |
| `server` | HTTP (OIDC endpoints, login pages, admin API) |
| `store/memstore`, `store/dynamostore` | Storage. Both pass the contract tests in `store/storetest` |
| `cmd/cogin` | The server, plus `gen-key`, `gen-pepper` and `new-client` |
| `cmd/cogin-lambda` | The Lambda entry point |

## License

MIT. See [LICENSE](LICENSE).

`server/web/static/vendor/jsQR.js` is [jsQR](https://github.com/cozmo/jsQR) 1.4.0 (Apache-2.0, see `jsQR.LICENSE.txt`).
