# Doorkeeper::IdJagGrant

Identity Assertion JWT Authorization Grant (ID-JAG) extension for
[Doorkeeper](https://github.com/doorkeeper-gem/doorkeeper).

ID-JAG ([`draft-ietf-oauth-identity-assertion-authz-grant`](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/))
lets an application obtain an access token for a third-party API through a
common enterprise identity provider. It builds on
[RFC 8693 (OAuth 2.0 Token Exchange)](https://datatracker.ietf.org/doc/html/rfc8693)
and [RFC 7523 (JWT Bearer grant)](https://datatracker.ietf.org/doc/html/rfc7523),
and the flow works in two steps:

1. A client exchanges an Identity Assertion (e.g. an OpenID Connect ID Token) for
   an ID-JAG at the **identity provider**.
2. The client presents the ID-JAG to a **resource authorization server** using
   the JWT Bearer grant to obtain an access token.

This gem provides both server roles as two Doorkeeper grant flows:

| Grant flow      | Role                          | Grant type                                          |
| --------------- | ----------------------------- | --------------------------------------------------- |
| `token_exchange`| IdP Authorization Server      | `urn:ietf:params:oauth:grant-type:token-exchange`   |
| `jwt_bearer`    | Resource Authorization Server | `urn:ietf:params:oauth:grant-type:jwt-bearer`       |

Both plug into Doorkeeper's existing token endpoint (`/oauth/token`); the gem
adds no new routes.

## Installation

This gem requires Doorkeeper `>= 6.0.0.beta1`, which introduced the RFC 8414
Authorization Server Metadata endpoint that this gem decorates (draft §7).
That version has not been released to RubyGems yet, so until Doorkeeper 6.0.0
ships, point your Gemfile at the `main` branch (or a released `6.0.0` once
available):

```ruby
gem "doorkeeper", github: "doorkeeper-gem/doorkeeper"
gem "doorkeeper-id_jag_grant"
```

Then run:

```bash
$ bundle install
```

Then run the install generator to place the configuration template:

```bash
$ rails generate doorkeeper:id_jag_grant:install
```

## How JWT crypto is handled

For the **Resource AS role** (`jwt_bearer`), this gem verifies ID-JAG assertions
with a **built-in verifier** backed by the [`jwt`](https://rubygems.org/gems/jwt)
gem: it checks the signature against the trusted issuer's key(s) and enforces
the draft §4.4.1 processing rules (typ, aud, exp/nbf/iat with clock skew,
required claims, `client_id` continuity, and optional replay protection). You
supply small hooks that answer "is this issuer trusted?", "what key verifies
it?", and "which local user does this subject map to?".

For the **IdP role** (`token_exchange`), signing an ID-JAG is delegated to an
`assertion_encoder` hook, because minting the grant requires decoding the
incoming subject token (an ID Token or SAML assertion) to resolve the
cross-domain subject — crypto that is deployment-specific.

If you'd rather bring your own JWT verification on the Resource AS side (for
example to reuse `doorkeeper-jwt` or a custom JWKS cache), set an
`assertion_decoder` hook; it fully replaces the built-in verifier while
Doorkeeper still applies the §4.4.1 claim checks on the decoded claims.

## Configuration

Enabling ID-JAG has two parts: enable the grant flow(s) in your **Doorkeeper**
initializer, and configure the ID-JAG options in a separate
**`Doorkeeper::IdJagGrant.configure`** block (typically in the same
`config/initializers/doorkeeper.rb`).

### Resource AS role (`jwt_bearer`) — built-in verifier

```ruby
Doorkeeper.configure do
  # ... your existing configuration ...
  grant_flows %w[authorization_code client_credentials jwt_bearer]
end

Doorkeeper::IdJagGrant.configure do
  # This server's own issuer identifier (RFC 8414). Every ID-JAG assertion must
  # present this as its `aud` claim. Falls back to `issuer` / Doorkeeper's core
  # `issuer` when not set. Required to issue tokens.
  audience "https://rs.example.com/"

  # Required: is `issuer` a trusted IdP? Fails closed (rejects) by default.
  trusted_issuer do |issuer|
    issuer == "https://idp.example.com/"
  end

  # Required: the verification key(s) for an issuer. Return a PEM String, an
  # OpenSSL::PKey, a JWK Hash, a JWT::JWK, or an Array of those. Fails closed.
  issuer_key do |issuer, kid|
    JwksCache.fetch(issuer).key(kid)
  end

  # Required: resolve the local resource owner (draft §4.4.1 subject resolution).
  # Return nil to reject the grant. Fails closed by default.
  resource_owner_from_assertion do |issuer, subject, client|
    User.find_by(idp_issuer: issuer, idp_subject: subject)
  end

  # Optional: application policy hook. Permissive by default.
  authorize do |client, resource_owner, scopes, claims|
    client.allowed_for?(resource_owner)
  end

  # Recommended: replay protection. Must respond to
  # #consume(jti, issuer, expires_at) and return true only on first use.
  replay_store MyReplayStore.new

  # Optional verifier tuning (defaults shown):
  # clock_skew 60
  # allowed_algorithms %w[RS256 ES256 PS256]  # `none`/HMAC are never accepted
  # allow_public_clients false                # ID-JAG §8.1; relax not recommended
end
```

### IdP role (`token_exchange`) — issue an ID-JAG

```ruby
Doorkeeper.configure do
  grant_flows %w[authorization_code client_credentials token_exchange]
end

Doorkeeper::IdJagGrant.configure do
  # Used as the issued ID-JAG `iss` claim.
  issuer "https://idp.example.com/"

  # Sign an ID-JAG. Receives a Doorkeeper::IdJagGrant::OAuth::IdJag::Claims
  # object (call #header / #payload) and a token exchange context, and must
  # return the signed compact JWT. Merge the resolved cross-domain `sub` into
  # the payload before signing.
  assertion_encoder do |claims, context|
    payload = claims.payload.merge("sub" => resolve_subject(context.subject_token))
    JWT.encode(payload, signing_key, "RS256", claims.header)
  end

  # Lifetime, in seconds, of an issued ID-JAG (draft §4.3.4 expires_in).
  expires_in 300

  # Optional: validate the subject token's audience is bound to the
  # requesting client (draft §4.3.3). Returning false/nil rejects the
  # exchange with `invalid_grant`. Default: nil (permissive).
  validate_subject_token do |subject_token, subject_token_type, application|
    case subject_token_type
    when "urn:ietf:params:oauth:token-type:id_token"
      # Resolve the IdP's JWKS for a trusted issuer before verifying (do not fetch
      # keys based solely on an unverified `iss` value).
      unverified_payload = JWT.decode(subject_token, nil, false).first
      jwks = jwks_for(unverified_payload["iss"]) # host: resolve issuer keys (e.g. JWKS URI)
      decoded = JWT.decode(subject_token, nil, true, algorithms: ["RS256"], jwks: jwks).first
      Array(decoded["aud"]).include?(application.uid)
    when "urn:ietf:params:oauth:token-type:refresh_token"
      # Ownership check only — lifecycle validation is deferred to
      # enforce_refresh_token_policy below.
      Doorkeeper::AccessToken.exists?(refresh_token: subject_token, application_id: application.id)
    end
  end

  # Optional: enforce refresh-token lifecycle policy when the
  # subject_token_type is a refresh token (draft §4.3.3). Returning
  # false/nil rejects the exchange with `invalid_grant`. Only invoked
  # for `urn:ietf:params:oauth:token-type:refresh_token`.
  # Default: nil (permissive).
  enforce_refresh_token_policy do |subject_token, application|
    token = Doorkeeper::AccessToken.find_by(refresh_token: subject_token)
    token&.application_id == application.id &&
      !token.expired? && !token.revoked?
  end
end
```

### Bring-your-own verification (Resource AS override)

```ruby
Doorkeeper::IdJagGrant.configure do
  audience "https://rs.example.com/"

  # Replaces the built-in verifier. Must fully verify signature + issuer trust
  # and return the decoded claims Hash, or raise / return nil to reject.
  assertion_decoder do |assertion, context|
    payload, _header = JWT.decode(assertion, nil, true, algorithms: ["RS256"], jwks: trusted_jwks)
    payload
  end

  # Subject resolution for the custom-decoder path.
  resolve_resource_owner do |claims, client|
    User.find_by(external_id: claims["sub"])
  end
end
```

### Configuration options

All options are set inside the `Doorkeeper::IdJagGrant.configure` block.

| Option                          | Role        | Description |
| ------------------------------- | ----------- | ----------- |
| `issuer`                        | both        | Issuer identifier of this server. IdP `iss`; Resource AS `aud` fallback. Falls back to Doorkeeper's core `issuer`. |
| `audience`                      | Resource AS | This server's issuer identifier; the expected `aud` of incoming assertions. Falls back to `issuer`. Required to issue tokens. |
| `trusted_issuer`                | Resource AS | Required `(issuer) -> Boolean`. Is the issuer a trusted IdP? Fails closed. |
| `issuer_key`                    | Resource AS | Required `(issuer, kid) -> key(s)`. PEM / `OpenSSL::PKey` / JWK Hash / `JWT::JWK` / Array. Fails closed. |
| `resource_owner_from_assertion` | Resource AS | Required `(issuer, subject, client) -> resource_owner`. Subject resolution. Fails closed. |
| `authorize`                     | Resource AS | Optional `(client, resource_owner, scopes, claims) -> Boolean` policy. Permissive by default. |
| `replay_store`                  | Resource AS | Optional store `#consume(jti, issuer, expires_at) -> Boolean`. `nil` disables replay protection (recommended to set). |
| `clock_skew`                    | Resource AS | Seconds of tolerance for `exp`/`nbf`/`iat`. Default `60`. |
| `allowed_algorithms`            | Resource AS | JWS algorithm allow-list. Default `%w[RS256 ES256 PS256]`; `none`/HMAC never accepted. |
| `allow_public_clients`          | Resource AS | Relax the ID-JAG §8.1 confidential-client restriction. Default `false`. |
| `assertion_decoder`             | Resource AS | Optional override of the built-in verifier: `(assertion, context) -> Hash`. |
| `resolve_resource_owner`        | Resource AS | Subject resolution for the `assertion_decoder` path: `(claims, client) -> resource_owner`. Defaults to `sub`. |
| `assertion_encoder`             | IdP         | `(claims, context) -> String` that signs and returns the compact ID-JAG JWT. |
| `expires_in`                    | IdP         | Lifetime (seconds) of an issued ID-JAG. Default `300`. |
| `validate_subject_token`        | IdP         | Optional `(subject_token, subject_token_type, Doorkeeper::Application) -> Boolean`. Validates the subject token's audience is bound to the requesting client (draft §4.3.3). Returns `invalid_grant` on rejection. Default: `nil` (permissive). |
| `enforce_refresh_token_policy`  | IdP         | Optional `(subject_token, Doorkeeper::Application) -> Boolean`. Enforces refresh-token lifecycle policy when `subject_token_type` is a refresh token (draft §4.3.3). Returns `invalid_grant` on rejection. Default: `nil` (permissive). Only invoked for `urn:ietf:params:oauth:token-type:refresh_token`. |

## Usage

### 1. Token Exchange — obtain an ID-JAG (IdP role)

```http
POST /oauth/token HTTP/1.1
Host: idp.example.com
Authorization: Basic <client credentials>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:id-jag
&audience=https://chat.example/
&resource=https://api.chat.example/
&scope=chat.read+chat.history
&subject_token=<ID Token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
```

Response (RFC 8693 §2.2 shape):

```json
{
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "access_token": "eyJ...",
  "token_type": "N_A",
  "scope": "chat.read chat.history",
  "expires_in": 300
}
```

Accepted `subject_token_type` values: `urn:ietf:params:oauth:token-type:id_token`
(required), `urn:ietf:params:oauth:token-type:saml2` and
`urn:ietf:params:oauth:token-type:refresh_token` (both optional, subject to your
encoder hook supporting them).

### 2. JWT Bearer — redeem an ID-JAG (Resource AS role)

```http
POST /oauth/token HTTP/1.1
Host: chat.example
Authorization: Basic <client credentials>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<ID-JAG>
```

Response (standard OAuth 2.0 token response):

```json
{
  "token_type": "Bearer",
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "expires_in": 7200,
  "scope": "chat.read chat.history"
}
```

The Resource Authorization Server enforces the draft §4.4.1 processing rules:
the JWT `typ` must be `oauth-id-jag+jwt`, the `aud` claim must match the
configured `issuer`, and the `client_id` claim must match the authenticated
client.

### Authorization Server Metadata (RFC 8414)

This gem augments Doorkeeper's RFC 8414 metadata endpoint response (draft §7):

* `identity_chaining_requested_token_types_supported` — advertised when the
  `token_exchange` flow is enabled.
* `authorization_grant_profiles_supported` — advertised when the `jwt_bearer`
  flow is enabled.

## Security notes

* ID-JAG is restricted to **confidential clients** by default (draft §8.1). The
  `jwt_bearer` grant rejects public clients unless `allow_public_clients` is
  enabled (not recommended for production). Public clients should use the
  interactive authorization code flow instead.
* The required `trusted_issuer`, `issuer_key` and `resource_owner_from_assertion`
  hooks **fail closed**: until you configure them, every `jwt_bearer` request is
  rejected. This prevents accidentally trusting unverified assertions.
* The built-in verifier never accepts `none` or HMAC (symmetric) algorithms — an
  ID-JAG is signed by an external IdP with an asymmetric key.
* Set a `replay_store` so an ID-JAG cannot be replayed within its validity
  window. Without one, replay protection is disabled (a startup warning is
  logged).
* Set `audience` (or `issuer`) so the `aud` claim is enforced; without it the
  Resource AS cannot assert its own identity and every request is rejected.
* No refresh token is ever issued for the `jwt_bearer` grant (draft §4.4.3);
  clients re-present the ID-JAG (or obtain a new one) when the access token
  expires.

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## License

The gem is available as open source under the terms of the
[MIT License](https://opensource.org/licenses/MIT).
