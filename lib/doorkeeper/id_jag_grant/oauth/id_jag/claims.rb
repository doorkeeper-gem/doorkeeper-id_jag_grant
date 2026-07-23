# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module OAuth
      module IdJag
        # Assembles the set of claims for an Identity Assertion JWT Authorization
        # Grant (ID-JAG) as described in §3.1 of
        # draft-ietf-oauth-identity-assertion-authz-grant.
        #
        # This class is concerned only with the *non-cryptographic* shape of the
        # grant: the JWT header `typ`, the required claims, and any granted
        # `scope` / `resource` / `authorization_details`. Signing the resulting
        # payload is delegated to the configured `assertion_encoder` hook.
        class Claims
          # RFC 8725 §3.11 typed JWT header value for an ID-JAG.
          TYP = "oauth-id-jag+jwt"

          attr_reader :issuer, :subject, :audience, :client_id, :resource,
                      :scope, :authorization_details, :expires_in, :extra_claims

          # rubocop:disable Metrics/ParameterLists
          def initialize(issuer:, subject:, audience:, client_id:,
                         resource: nil, scope: nil, authorization_details: nil,
                         expires_in: 300, extra_claims: {})
            @issuer = issuer
            @subject = subject
            @audience = audience
            @client_id = client_id
            @resource = resource
            @scope = scope
            @authorization_details = authorization_details
            @expires_in = expires_in
            @extra_claims = extra_claims || {}
          end
          # rubocop:enable Metrics/ParameterLists

          # The JWT header parameters. The `typ` is required by the draft; the
          # signing algorithm and key id are the encoder's responsibility.
          def header
            { "typ" => TYP }
          end

          # The JWT payload. Optional claims are only included when present, and
          # any encoder-supplied extra claims (e.g. `email`, `auth_time`, `act`,
          # `cnf`) are merged last so a hook can enrich the grant.
          def payload(now: Time.now.utc)
            issued_at = now.to_i

            {
              "jti" => Doorkeeper::OAuth::Helpers::UniqueToken.generate,
              "iss" => issuer,
              "sub" => subject,
              "aud" => audience,
              "client_id" => client_id,
              "iat" => issued_at,
              "exp" => issued_at + expires_in.to_i,
              "resource" => resource,
              "scope" => scope.presence,
              "authorization_details" => authorization_details,
            }.compact.merge(stringify(extra_claims))
          end

          private

          def stringify(hash)
            hash.each_with_object({}) { |(k, v), acc| acc[k.to_s] = v }
          end
        end
      end
    end
  end
end
