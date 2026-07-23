# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module OAuth
      # RFC 8693 §2.2 token exchange response, profiled for an Identity Assertion
      # JWT Authorization Grant (draft §4.3.4). The signed ID-JAG is returned in
      # the +access_token+ member (as RFC 8693 requires) with +token_type+ of
      # "N_A" because it is not an OAuth access token.
      class IdentityAssertionResponse < Doorkeeper::OAuth::BaseResponse
        attr_reader :assertion, :scope, :expires_in, :authorization_details

        def initialize(assertion:, scope: nil, expires_in: nil, authorization_details: nil)
          super()
          @assertion = assertion
          @scope = scope
          @expires_in = expires_in
          @authorization_details = authorization_details
        end

        def body
          @body ||= {
            "issued_token_type" => Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_JAG,
            "access_token" => assertion,
            "token_type" => "N_A",
            "scope" => scope.presence,
            "expires_in" => expires_in,
            "authorization_details" => authorization_details,
          }.reject { |_, value| value.blank? }
        end

        def status
          :ok
        end

        def headers
          {
            "Cache-Control" => "no-store, no-cache",
            "Content-Type" => "application/json; charset=utf-8",
            "Pragma" => "no-cache",
          }
        end
      end
    end
  end
end
