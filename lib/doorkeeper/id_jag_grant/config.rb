# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    # Configures the extension.
    #
    # @yield the configuration block, evaluated against a +Config::Builder+
    # @return [Doorkeeper::IdJagGrant::Config]
    def self.configure(&block)
      @config = Config::Builder.new(Config.new, &block).build
    end

    # @return [Doorkeeper::IdJagGrant::Config] the current configuration
    # @raise [MissingConfiguration] when the extension has not been configured
    def self.configuration
      @config || (raise MissingConfiguration)
    end

    # @return [Boolean] whether the extension has been configured
    def self.configured?
      !@config.nil?
    end

    # Resets the configuration. Primarily useful for test isolation.
    # @return [void]
    def self.reset_configuration!
      @config = nil
    end

    # Error raised in case of missing configuration.
    class MissingConfiguration < StandardError
      def initialize
        super(
          "Configuration for Doorkeeper::IdJagGrant missing. " \
          "Do you have a Doorkeeper::IdJagGrant.configure initializer?",
        )
      end
    end

    # Configuration model for the Identity Assertion JWT Authorization Grant
    # (ID-JAG) extension. Mirrors the structure of Doorkeeper's own +Config+:
    # a dedicated +Builder+ subclassing +Doorkeeper::Config::AbstractBuilder+
    # and options declared through +Doorkeeper::Config::Option+.
    class Config
      # Default lifetime, in seconds, of an issued ID-JAG (draft §4.3.4).
      DEFAULT_EXPIRES_IN = 300

      # Default subject resolution: use the ID-JAG `sub` claim as-is.
      DEFAULT_RESOLVE_RESOURCE_OWNER = ->(claims, _client) { claims["sub"] }

      # Signature algorithms accepted by the built-in verifier. `none` and the
      # symmetric HMAC family are deliberately excluded: an ID-JAG is signed by
      # an external IdP with an asymmetric key, so accepting HMAC would let a
      # party that only knows the (public) verification key forge assertions.
      DEFAULT_ALLOWED_ALGORITHMS = %w[RS256 ES256 PS256].freeze

      # Default clock-skew tolerance, in seconds, for exp/nbf/iat checks.
      DEFAULT_CLOCK_SKEW = 60

      # Fail-closed default for a required hook: warns once (per call) and
      # returns +result+. Mirrors the official Doorkeeper PR #1861 behaviour so
      # a server that enables the flow without configuring the required hooks
      # rejects every request instead of trusting unverified input.
      def self.unconfigured(option_name, result = nil)
        lambda do |*|
          ::Rails.logger.warn("[DOORKEEPER-ID-JAG] #{option_name} is not configured") if defined?(::Rails)
          result
        end
      end

      class Builder < Doorkeeper::Config::AbstractBuilder
      end

      def self.builder_class
        Config::Builder
      end

      extend Doorkeeper::Config::Option

      # @!attribute [r] issuer
      #   The issuer identifier of this Authorization Server. Used as the ID-JAG
      #   `iss` claim (IdP role). For the Resource AS role, the expected `aud`
      #   is +audience+ (which itself falls back to this +issuer+). When blank,
      #   +#issuer_value+ falls back to Doorkeeper's own +issuer+ option.
      #   @return [String, nil]
      option :issuer, default: nil

      # @!attribute [r] audience
      #   Resource AS role: this server's own issuer identifier (RFC 8414), which
      #   every ID-JAG assertion must present as its `aud` claim (draft §4.4.1).
      #   Falls back to +issuer_value+ when not set. Required to issue tokens.
      #   @return [String, nil]
      option :audience, default: nil

      # @!attribute [r] clock_skew
      #   Resource AS role: clock-skew tolerance, in seconds, applied to the
      #   `exp`, `nbf` and `iat` claim checks.
      #   @return [Integer]
      option :clock_skew, default: DEFAULT_CLOCK_SKEW

      # @!attribute [r] allowed_algorithms
      #   Resource AS role: JWS signature algorithm allow-list for the built-in
      #   verifier. `none` and HMAC are never accepted.
      #   @return [Array<String>]
      option :allowed_algorithms, default: DEFAULT_ALLOWED_ALGORITHMS

      # @!attribute [r] allow_public_clients
      #   Resource AS role: ID-JAG §8.1 restricts this grant to confidential
      #   clients. Set true to relax (not recommended for production).
      #   @return [Boolean]
      option :allow_public_clients, default: false

      # @!attribute [r] trusted_issuer
      #   Resource AS role: required `(issuer) -> Boolean` hook answering whether
      #   +issuer+ is a trusted IdP. Fails closed (rejects) by default.
      #   @return [#call]
      option :trusted_issuer, default: unconfigured(:trusted_issuer, false)

      # @!attribute [r] issuer_key
      #   Resource AS role: required `(issuer, kid) -> key(s)` hook returning the
      #   verification key(s) for the issuer: a PEM String, an OpenSSL::PKey, a
      #   JWK Hash, a JWT::JWK, or an Array of those. Fails closed by default.
      #   @return [#call]
      option :issuer_key, default: unconfigured(:issuer_key)

      # @!attribute [r] resource_owner_from_assertion
      #   Resource AS role: required `(issuer, subject, client) -> resource_owner`
      #   hook resolving the local resource owner (draft §4.4.1 subject
      #   resolution). Fails closed by default. Return nil to reject the grant.
      #   @return [#call]
      option :resource_owner_from_assertion, default: unconfigured(:resource_owner_from_assertion)

      # @!attribute [r] authorize
      #   Resource AS role: optional `(client, resource_owner, scopes, claims) ->
      #   Boolean` policy hook. Permissive by default.
      #   @return [#call]
      option :authorize, default: ->(_client, _resource_owner, _scopes, _claims) { true }

      # @!attribute [r] replay_store
      #   Resource AS role: optional replay-protection store responding to
      #   `#consume(jti, issuer, expires_at) -> Boolean` (true only on first use
      #   of an `(issuer, jti)` pair). nil disables replay protection (a startup
      #   warning is logged); supplying an app-backed store is recommended.
      #   @return [#consume, nil]
      option :replay_store, default: nil

      # @!attribute [r] validate_subject_token
      #   IdP role: optional `(subject_token, subject_token_type, Doorkeeper::Application) -> Boolean`
      #   hook that validates the subject token's audience is bound to the
      #   requesting client (draft §4.3.3). For JWT subject tokens the `aud`
      #   claim MUST match the client; for SAML assertions the audience MUST
      #   match; for refresh tokens the token MUST belong to the client.
      #   Returning false/nil rejects the exchange with +invalid_target+.
      #   @return [#call, nil]
      option :validate_subject_token, default: nil

      # @!attribute [r] enforce_refresh_token_policy
      #   IdP role: optional `(subject_token, Doorkeeper::Application) -> Boolean` hook that
      #   enforces refresh-token lifecycle policy when the +subject_token_type+
      #   is a refresh token (draft §4.3.3). The host application is expected to
      #   look up the refresh token, verify it belongs to the client and is not
      #   expired/revoked, and determine whether the exchange is permitted.
      #   Returning false/nil rejects the exchange with +invalid_grant+.
      #   @return [#call, nil]
      option :enforce_refresh_token_policy, default: nil

      # @!attribute [r] assertion_encoder
      #   IdP role: signs an ID-JAG. A callable +(claims, context) -> String+
      #   that receives a {Doorkeeper::IdJagGrant::OAuth::IdJag::Claims} object
      #   and a {Doorkeeper::IdJagGrant::OAuth::IdJag::TokenExchangeContext}, and
      #   returns the signed compact JWT. Because resolving the cross-domain
      #   `sub` requires decoding the subject token (JWT/SAML crypto that lives
      #   outside this gem), the hook is expected to merge the authoritative
      #   `sub` into the payload before signing.
      #   @return [#call, nil]
      option :assertion_encoder, default: nil

      # @!attribute [r] assertion_decoder
      #   Resource AS role: OPTIONAL override of the built-in JWT verification.
      #   A callable +(assertion, context) -> Hash+ that fully verifies the
      #   assertion (signature, issuer trust, claims) and returns the decoded
      #   claims, or nil/raises to reject. When set, it replaces the built-in
      #   verifier and the +trusted_issuer+/+issuer_key+/+allowed_algorithms+/
      #   +clock_skew+/+replay_store+/+audience+ options for decoding. Leave nil
      #   to use the built-in verifier (recommended).
      #   @return [#call, nil]
      option :assertion_decoder, default: nil

      # @!attribute [r] resolve_resource_owner
      #   Resource AS role: subject resolution used with the OPTIONAL
      #   +assertion_decoder+ path. A callable +(claims, client) ->
      #   resource_owner+. Defaults to the `sub` claim. When the built-in
      #   verifier is used, +resource_owner_from_assertion+ is used instead.
      #   @return [#call]
      option :resolve_resource_owner, default: DEFAULT_RESOLVE_RESOURCE_OWNER

      # @!attribute [r] expires_in
      #   IdP role: lifetime, in seconds, of an issued ID-JAG (draft §4.3.4).
      #   @return [Integer]
      option :expires_in, default: DEFAULT_EXPIRES_IN

      # The effective issuer identifier for ID-JAG. Prefers this extension's
      # +issuer+ option and falls back to Doorkeeper's core +issuer+ option.
      #
      # @return [String, nil]
      def issuer_value
        issuer.presence || Doorkeeper.config.issuer
      end

      # The expected `aud` for incoming ID-JAG assertions (Resource AS role).
      # Prefers the explicit +audience+ option and falls back to +issuer_value+.
      #
      # @return [String, nil]
      def audience_value
        return audience if audience.present?

        issuer_value
      end

      # Whether the host application supplied its own +assertion_decoder+,
      # bypassing the built-in JWT verifier.
      #
      # @return [Boolean]
      def custom_assertion_decoder?
        assertion_decoder.respond_to?(:call)
      end

      # Emits startup warnings for risky-but-valid configurations. Invoked by
      # +Config::Builder#build+ (via +AbstractBuilder+). Only warns for the
      # Resource AS role, and only when the built-in verifier is in use.
      #
      # @return [void]
      def validate!
        return if custom_assertion_decoder?
        return unless jwt_bearer_flow_enabled?

        warn_missing_audience
        warn_missing_replay_store
      end

      private

      def jwt_bearer_flow_enabled?
        return false unless Doorkeeper.configured?

        Doorkeeper.config.grant_flows.map(&:to_s).include?("jwt_bearer")
      rescue StandardError
        false
      end

      def warn_missing_audience
        return if audience_value.present?

        logger_warn(
          "The jwt_bearer grant flow is enabled but no audience/issuer is configured. " \
          "Every ID-JAG assertion's `aud` claim check will fail, so every jwt_bearer request " \
          "will be rejected until you set `audience` to this Resource AS's own issuer identifier.",
        )
      end

      def warn_missing_replay_store
        return if replay_store

        logger_warn(
          "The jwt_bearer grant flow is enabled without a replay_store. ID-JAG assertions " \
          "will not be protected against replay within their validity window. Supplying an " \
          "app-backed store that responds to #consume(jti, issuer, expires_at) is recommended.",
        )
      end

      def logger_warn(message)
        return unless defined?(::Rails) && ::Rails.respond_to?(:logger) && ::Rails.logger

        ::Rails.logger.warn("[DOORKEEPER-ID-JAG] #{message}")
      end
    end
  end
end
