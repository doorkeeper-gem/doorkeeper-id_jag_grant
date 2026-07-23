# frozen_string_literal: true

require "json"

module Doorkeeper
  module IdJagGrant
    module OAuth
      # IdP Authorization Server side of the Identity Assertion JWT Authorization
      # Grant (draft-ietf-oauth-identity-assertion-authz-grant §4.3): a confidential
      # client presents an Identity Assertion (or, when supported, a Refresh Token)
      # through an RFC 8693 Token Exchange request and receives a signed ID-JAG.
      #
      # This class owns the non-cryptographic protocol: validating the token
      # exchange parameters, checking the requested/subject token types, deriving
      # the granted scopes and resource, and assembling the claims. The actual
      # signing is delegated to the configured +assertion_encoder+ hook.
      class IdentityAssertionRequest < Doorkeeper::OAuth::BaseRequest
        include Doorkeeper::OAuth::Helpers

        # subject_token types accepted as input to the exchange. ID Tokens MUST
        # be accepted; SAML 2.0 assertions and Refresh Tokens MAY be accepted
        # (draft §4.3, subject_token).
        ACCEPTED_SUBJECT_TOKEN_TYPES = [
          Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_TOKEN,
          Doorkeeper::IdJagGrant::TOKEN_TYPE_SAML2,
          Doorkeeper::IdJagGrant::TOKEN_TYPE_REFRESH_TOKEN,
        ].freeze

        validate :params, error: Doorkeeper::Errors::InvalidRequest
        validate :client, error: Doorkeeper::Errors::InvalidClient
        validate :client_supports_grant_flow, error: Doorkeeper::Errors::UnauthorizedClient
        validate :requested_token_type, error: Doorkeeper::IdJagGrant::Errors::UnsupportedTokenType
        validate :subject_token_type, error: Doorkeeper::Errors::InvalidRequest
        validate :actor_token_type, error: Doorkeeper::Errors::InvalidRequest
        validate :authorization_details, error: Doorkeeper::Errors::InvalidRequest
        validate :encoder_configured, error: Doorkeeper::Errors::InvalidRequest
        validate :scopes, error: Doorkeeper::Errors::InvalidScope

        attr_reader :client, :parameters, :missing_param, :response

        alias error_response response

        def initialize(server, client, parameters = {})
          super()
          @server = server
          @client = client
          @parameters = parameters
          @grant_type = Doorkeeper::IdJagGrant::GRANT_TYPE_TOKEN_EXCHANGE
          @requested_token_type = parameters[:requested_token_type]
          @subject_token = parameters[:subject_token]
          @subject_token_type = parameters[:subject_token_type]
          @actor_token = parameters[:actor_token]
          @actor_token_type = parameters[:actor_token_type]
          @audience = parameters[:audience]
          @resource = parameters[:resource]
          @authorization_details = parameters[:authorization_details]
          @original_scopes = parameters[:scope]
        end

        # Overrides BaseRequest#authorize: a Token Exchange for an ID-JAG returns
        # the signed grant (RFC 8693 §2.2 response shape), not an access token.
        def authorize
          if valid?
            before_successful_response
            @response = IdentityAssertionResponse.new(
              assertion: issue_assertion,
              scope: scopes.to_s,
              expires_in: id_jag_config.expires_in,
              authorization_details: @authorization_details,
            )
            after_successful_response
            @response
          elsif error == Doorkeeper::Errors::InvalidRequest
            @response = Doorkeeper::OAuth::InvalidRequestResponse.from_request(self)
          else
            @response = Doorkeeper::OAuth::ErrorResponse.from_request(self)
          end
        end

        private

        def id_jag_config
          Doorkeeper::IdJagGrant.configuration
        end

        def issue_assertion
          claims = IdJag::Claims.new(
            issuer: id_jag_issuer,
            subject: subject_identifier,
            audience: @audience,
            client_id: client.uid,
            resource: @resource,
            scope: scopes.to_s.presence,
            authorization_details: @authorization_details,
            expires_in: id_jag_config.expires_in,
          )

          id_jag_config.assertion_encoder.call(claims, token_exchange_context)
        end

        def token_exchange_context
          IdJag::TokenExchangeContext.new(
            client: client.application,
            subject_token: @subject_token,
            subject_token_type: @subject_token_type,
            actor_token: @actor_token,
            actor_token_type: @actor_token_type,
            audience: @audience,
            resource: @resource,
            scopes: scopes,
            authorization_details: @authorization_details,
            parameters: parameters,
          )
        end

        # The ID-JAG `iss` (draft §3.1) is the IdP Authorization Server's issuer
        # identifier. Uses the ID-JAG issuer (falling back to core's `issuer`).
        def id_jag_issuer
          id_jag_config.issuer_value
        end

        # Doorkeeper cannot resolve a cross-domain subject identifier without
        # decoding the subject token (which needs the JWT/SAML crypto that lives
        # outside core). The encoder hook receives the full context and is
        # expected to set the authoritative `sub`; this placeholder is only used
        # when the hook does not override it.
        def subject_identifier
          nil
        end

        def validate_params
          @missing_param =
            if @requested_token_type.blank?
              :requested_token_type
            elsif @subject_token.blank?
              :subject_token
            elsif @subject_token_type.blank?
              :subject_token_type
            elsif @audience.blank?
              :audience
            end

          @missing_param.nil?
        end

        def validate_client
          client.present?
        end

        def validate_client_supports_grant_flow
          Doorkeeper.config.allow_grant_flow_for_client?(grant_type, client&.application)
        end

        # Only the ID-JAG requested_token_type is supported by this profile.
        def validate_requested_token_type
          @requested_token_type == Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_JAG
        end

        def validate_subject_token_type
          ACCEPTED_SUBJECT_TOKEN_TYPES.include?(@subject_token_type)
        end

        def validate_actor_token_type
          return true if @actor_token.blank?

          @actor_token_type.present?
        end

        def validate_authorization_details
          return true if @authorization_details.blank?
          return true if @authorization_details.is_a?(Array)
          return false unless @authorization_details.is_a?(String)

          parsed = JSON.parse(@authorization_details)
          return false unless parsed.is_a?(Array)

          @authorization_details = parsed
          true
        rescue JSON::ParserError
          false
        end

        def validate_encoder_configured
          id_jag_config.assertion_encoder.respond_to?(:call)
        end

        def validate_scopes
          return true if scopes.blank?

          ScopeChecker.valid?(
            scope_str: scopes.to_s,
            server_scopes: server.scopes,
            app_scopes: client.try(:scopes),
            grant_type: grant_type,
          )
        end
      end
    end
  end
end
