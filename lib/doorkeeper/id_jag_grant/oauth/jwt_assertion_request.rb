# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module OAuth
      # Resource Authorization Server side of the Identity Assertion JWT
      # Authorization Grant (draft §4.4): the client presents a previously issued
      # ID-JAG as an RFC 7523 JWT Bearer +assertion+ and receives an access token.
      #
      # By default the assertion is verified by the built-in JWT verifier
      # ({Helpers::JwtBearerAssertion}), which checks the signature against the
      # trusted issuer's key(s) and enforces the draft §4.4.1 processing rules
      # (typ, aud, exp/nbf/iat, required claims, client_id continuity, replay).
      # A host application MAY instead supply its own +assertion_decoder+ hook to
      # bring its own crypto; in that case Doorkeeper applies the §4.4.1 claim
      # checks on the returned claims.
      class JwtAssertionRequest < Doorkeeper::OAuth::BaseRequest
        include Doorkeeper::OAuth::Helpers

        validate :params, error: Doorkeeper::Errors::InvalidRequest
        validate :client, error: Doorkeeper::Errors::InvalidClient
        validate :client_supports_grant_flow, error: Doorkeeper::Errors::UnauthorizedClient
        validate :confidential_client, error: Doorkeeper::Errors::UnauthorizedClient
        validate :assertion, error: Doorkeeper::Errors::InvalidGrant
        validate :resource_owner, error: Doorkeeper::Errors::InvalidGrant
        validate :authorized, error: Doorkeeper::Errors::UnauthorizedClient
        validate :scopes, error: Doorkeeper::Errors::InvalidScope

        attr_reader :client, :parameters, :missing_param, :access_token, :claims

        def initialize(server, client, parameters = {})
          super()
          @server = server
          @client = client
          @parameters = parameters
          @grant_type = Doorkeeper::IdJagGrant::GRANT_TYPE_JWT_BEARER
          @assertion = parameters[:assertion]
          # §4.4 does not define a scope request parameter; the granted scopes are
          # derived from the ID-JAG `scope` claim (which the RS MAY narrow).
          @original_scopes = nil
        end

        private

        def before_successful_response
          find_or_create_access_token(client, resource_owner, scopes, {}, server)
          super
        end

        def id_jag_config
          Doorkeeper::IdJagGrant.configuration
        end

        # Verify + decode the assertion once, memoised. Uses the built-in JWT
        # verifier unless the host supplied a custom +assertion_decoder+ hook.
        # Any failure (bad signature, untrusted issuer, failed claim checks,
        # or a hook error) collapses to nil so the grant is rejected with
        # invalid_grant without leaking which check failed.
        def decoded_claims
          return @decoded_claims if defined?(@decoded_claims)

          @decoded_claims =
            if id_jag_config.custom_assertion_decoder?
              decode_with_custom_hook
            else
              decode_with_builtin_verifier
            end
        end

        def decode_with_builtin_verifier
          result = Helpers::JwtBearerAssertion.verify(
            @assertion,
            client: client,
            config: id_jag_config,
          )
          result.success? ? result.claims : nil
        end

        # The custom decoder is fully responsible for verifying the signature
        # and issuer trust; Doorkeeper then applies the §4.4.1 claim checks
        # (typ, aud, client_id continuity) on the returned claims here.
        def decode_with_custom_hook
          claims =
            begin
              result = id_jag_config.assertion_decoder.call(@assertion, assertion_context)
              result.is_a?(Hash) ? result.transform_keys(&:to_s) : nil
            rescue StandardError
              nil
            end
          return nil unless claims
          return nil unless valid_custom_claims?(claims)

          claims
        end

        # §4.4.1 claim checks applied to the custom-decoder path (the built-in
        # verifier already enforces these during decode).
        def valid_custom_claims?(claims)
          typ_ok = claims["typ"].nil? || claims["typ"] == IdJag::Claims::TYP
          typ_ok && valid_audience?(claims) && claims["client_id"] == client.uid
        end

        # §4.4.1: the `aud` claim MUST identify this Resource Authorization
        # Server. It may be a string or a single-element array.
        def valid_audience?(claims)
          expected = id_jag_config.audience_value
          return true if expected.blank?

          aud = claims["aud"]
          aud = aud.first if aud.is_a?(Array) && aud.size == 1
          aud == expected
        end

        def assertion_context
          IdJag::AssertionContext.new(
            client: client&.application,
            assertion: @assertion,
            parameters: parameters,
          )
        end

        def resource_owner
          return @resource_owner if defined?(@resource_owner)

          @resource_owner = claims && resolve_resource_owner
        end

        def resolve_resource_owner
          if id_jag_config.custom_assertion_decoder?
            id_jag_config.resolve_resource_owner.call(claims, client&.application)
          else
            id_jag_config.resource_owner_from_assertion.call(
              claims["iss"], claims["sub"], client&.application,
            )
          end
        end

        def validate_params
          @missing_param = :assertion if @assertion.blank?
          @missing_param.nil?
        end

        def validate_client
          client.present?
        end

        def validate_client_supports_grant_flow
          Doorkeeper.config.allow_grant_flow_for_client?(grant_type, client&.application)
        end

        # ID-JAG §8.1: the grant is restricted to confidential clients unless
        # explicitly relaxed via +allow_public_clients+.
        def validate_confidential_client
          return true if id_jag_config.allow_public_clients
          return true unless client&.application.respond_to?(:confidential?)

          client.application.confidential?
        end

        # Populates #claims via the verifier; rejects when verification fails.
        def validate_assertion
          @claims = decoded_claims
          @claims.present?
        end

        def validate_resource_owner
          resource_owner.present?
        end

        # Optional application policy hook (draft §4.4.1 "The Resource
        # Authorization Server still applies local policy").
        def validate_authorized
          id_jag_config.authorize.call(client&.application, resource_owner, scopes, claims)
        end

        # §4.4.1: the RS MAY narrow the scopes from the ID-JAG. Validate that the
        # scopes granted in the assertion are known to the server / client.
        def validate_scopes
          return true if scopes.blank?

          ScopeChecker.valid?(
            scope_str: scopes.to_s,
            server_scopes: server.scopes,
            app_scopes: client.try(:scopes),
            grant_type: grant_type,
          )
        end

        # Scopes come from the ID-JAG `scope` claim rather than a request
        # parameter (§4.4 defines no scope parameter).
        def build_scopes
          Doorkeeper::OAuth::Scopes.from_string(claims["scope"].to_s)
        end
      end
    end
  end
end
