# frozen_string_literal: true

require "doorkeeper"

require "doorkeeper/id_jag_grant/version"
require "doorkeeper/id_jag_grant/config"
require "doorkeeper/id_jag_grant/errors"

module Doorkeeper
  # Identity Assertion JWT Authorization Grant (ID-JAG) extension for Doorkeeper.
  #
  # draft-ietf-oauth-identity-assertion-authz-grant
  #
  # ID-JAG lets an application obtain an access token for a third-party API
  # through a common enterprise identity provider. It builds on RFC 8693 (OAuth
  # 2.0 Token Exchange) and RFC 7523 (JWT Bearer grant), and is realised as two
  # complementary Doorkeeper grant flows:
  #
  #   * +token_exchange+ - the IdP Authorization Server role: exchanges an
  #     Identity Assertion (ID Token / SAML assertion / refresh token) for a
  #     signed ID-JAG via RFC 8693 Token Exchange.
  #   * +jwt_bearer+ - the Resource Authorization Server role: redeems an ID-JAG
  #     for an access token via the RFC 7523 JWT Bearer grant.
  #
  # For the Resource AS role, assertions are verified by a built-in JWT
  # verifier; for the IdP role, signing is delegated to an +assertion_encoder+
  # hook set via +Doorkeeper::IdJagGrant.configure+. See
  # +Doorkeeper::IdJagGrant::Config+.
  module IdJagGrant
    # Token type identifiers (RFC 8693 §3) used by ID-JAG.
    TOKEN_TYPE_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
    TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    TOKEN_TYPE_SAML2 = "urn:ietf:params:oauth:token-type:saml2"
    TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"

    # Grant type identifiers.
    GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"

    # Authorization grant profile identifier advertised by a Resource
    # Authorization Server that implements the ID-JAG profile (draft §7).
    GRANT_PROFILE_ID_JAG = "urn:ietf:params:oauth:grant-profile:id-jag"

    autoload :Request, "doorkeeper/id_jag_grant/request"

    module OAuth
      autoload :IdentityAssertionRequest, "doorkeeper/id_jag_grant/oauth/identity_assertion_request"
      autoload :IdentityAssertionResponse, "doorkeeper/id_jag_grant/oauth/identity_assertion_response"
      autoload :JwtAssertionRequest, "doorkeeper/id_jag_grant/oauth/jwt_assertion_request"
      autoload :MetadataResponseExtension, "doorkeeper/id_jag_grant/oauth/metadata_response_extension"

      module IdJag
        autoload :Claims, "doorkeeper/id_jag_grant/oauth/id_jag/claims"
        autoload :TokenExchangeContext, "doorkeeper/id_jag_grant/oauth/id_jag/token_exchange_context"
        autoload :AssertionContext, "doorkeeper/id_jag_grant/oauth/id_jag/assertion_context"
      end

      module Helpers
        autoload :JwtBearerAssertion, "doorkeeper/id_jag_grant/oauth/helpers/jwt_bearer_assertion"
      end
    end

    class << self
      # Registers the two grant flows with Doorkeeper and decorates the RFC
      # 8414 metadata response to advertise the ID-JAG metadata parameters.
      # Requiring this file already triggers this via the call at the bottom,
      # so applications normally never need to call it directly.
      def install!
        Doorkeeper::GrantFlow.register(
          :token_exchange,
          grant_type_matches: GRANT_TYPE_TOKEN_EXCHANGE,
          grant_type_strategy: Request::TokenExchange,
        )

        Doorkeeper::GrantFlow.register(
          :jwt_bearer,
          grant_type_matches: GRANT_TYPE_JWT_BEARER,
          grant_type_strategy: Request::JwtBearer,
        )

        Doorkeeper::OAuth::MetadataResponse.prepend(OAuth::MetadataResponseExtension)
      end
    end
  end
end

require "doorkeeper/id_jag_grant/engine" if defined?(Rails::Engine)

# Wire the extension into Doorkeeper as soon as the gem is loaded, so the grant
# flows are registered before the host application's +Doorkeeper.configure+
# block runs.
Doorkeeper::IdJagGrant.install!

# Provide a default (empty) configuration so the grant flows degrade gracefully
# when the host application has not called +Doorkeeper::IdJagGrant.configure+:
# with the required hooks unset, requests fail closed instead of raising. An
# explicit +configure+ call replaces this.
Doorkeeper::IdJagGrant.configure { nil } unless Doorkeeper::IdJagGrant.configured?
