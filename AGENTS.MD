# Doorkeeper ID-JAG Grant Codebase Guide for AI Agents

`doorkeeper-id_jag_grant` is a Doorkeeper extension gem that implements the
Identity Assertion JWT Authorization Grant (ID-JAG) draft flow using OAuth 2.0
Token Exchange and JWT Bearer grant semantics.

* Treat OAuth protocol correctness and security requirements as the primary constraint.
* Keep behavior aligned with the relevant standards and draft sections used by this gem:
  RFC 6749, RFC 7523, RFC 8414, RFC 8693, and
  `draft-ietf-oauth-identity-assertion-authz-grant`.
* Prefer compatibility-safe changes. This gem is integrated into host apps
  through Doorkeeper; avoid breaking public configuration, grant behavior, token
  response shape, and metadata output unless explicitly required.

## Codebase map

* `lib/doorkeeper/id_jag_grant.rb` is the entry point and integration hook.
* `lib/doorkeeper/id_jag_grant/config.rb` defines extension configuration and defaults.
* `lib/doorkeeper/id_jag_grant/engine.rb` wires Rails engine integration.
* `lib/doorkeeper/id_jag_grant/request/**` contains request strategy parsing for grant types.
* `lib/doorkeeper/id_jag_grant/oauth/**` contains grant request/response logic, assertion validation, claim/context objects, and metadata extension behavior.
* `lib/doorkeeper/id_jag_grant/errors.rb` contains extension-specific error definitions.

## Test map

* Grant and metadata endpoint behavior: `spec/requests/**`
* OAuth helpers and claim processing: `spec/lib/oauth/**`
* Configuration behavior: `spec/lib/config_spec.rb`
* Shared test helpers: `spec/support/**`
* Integration app used by request specs: `spec/dummy/**`

Reuse existing helpers and factories before adding new test setup.

## Build, lint, and test commands

From repository root:

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

Useful targeted command:

```bash
bundle exec rspec spec/path/to/file_spec.rb
```

## Coding conventions

* Follow `.rubocop.yml`.
* Keep `# frozen_string_literal: true` and prefer double-quoted strings.
* Preserve naming and directory conventions used by Doorkeeper extension code:
  request strategy logic under `request/**`, protocol logic under `oauth/**`,
  and integration/configuration code at top-level files.

## Change guidance

* Make surgical changes and add/update specs close to changed behavior.
* For protocol behavior changes, verify related request specs and supporting lib
  specs move together.
* Do not weaken validation, issuer trust checks, signature verification,
  audience/client continuity checks, or replay protections silently.
* Keep fail-closed behavior for security-critical configuration hooks unless a
  task explicitly changes that contract.

## Documentation and changelog

* For user-visible behavior changes, add an entry under `CHANGELOG.md`.
* Update `README.md` when public configuration, supported behavior, or usage
  examples change.

## Practical workflow tips

* Prefer existing rake tasks and repository tooling over custom scripts.
* Verify assumptions against current files in this repository; do not assume
  older examples or upstream docs are still accurate for this extension.
