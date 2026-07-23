# Changelog

## main

- Initial release. Adds support for the Identity Assertion JWT Authorization
  Grant (ID-JAG), `draft-ietf-oauth-identity-assertion-authz-grant`, as a
  Doorkeeper extension. Requires Doorkeeper `>= 6.0.0.beta1` (for its RFC 8414
  Authorization Server Metadata endpoint, which is not yet published to
  RubyGems — see the Installation section for pointing at `main` in the
  meantime).
  - New `token_exchange` grant flow (IdP role): issues a signed ID-JAG from an
    Identity Assertion via RFC 8693 Token Exchange, using an `assertion_encoder`
    hook to sign.
  - New `jwt_bearer` grant flow (Resource Authorization Server role): redeems an
    ID-JAG for an access token via the RFC 7523 JWT Bearer grant, with a
    **built-in JWT verifier** (depends on the `jwt` gem) that checks the
    signature against the trusted issuer's key(s) and enforces the draft §4.4.1
    processing rules (typ, aud, exp/nbf/iat with clock skew, required claims,
    `client_id` continuity, replay). Never issues a refresh token (draft §4.4.3).
  - Resource AS configuration (set via `Doorkeeper::IdJagGrant.configure`):
    required `trusted_issuer`, `issuer_key`, `resource_owner_from_assertion`
    (all fail closed); `audience`; optional `authorize` policy hook,
    `replay_store`, `clock_skew`, `allowed_algorithms`, `allow_public_clients`
    (confidential-client-only by default per §8.1). An optional
    `assertion_decoder` hook replaces the built-in verifier with bring-your-own
    crypto.
  - IdP configuration: `issuer`, `assertion_encoder`, `expires_in`.
  - Advertises the ID-JAG RFC 8414 metadata parameters
    (`identity_chaining_requested_token_types_supported` and
    `authorization_grant_profiles_supported`).
  - [#2] Explicit subject token validation hooks for IdP-side token exchange.