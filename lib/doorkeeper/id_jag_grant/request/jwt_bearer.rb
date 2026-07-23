# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module Request
      # RFC 7523 JWT Bearer strategy. In the Identity Assertion JWT Authorization
      # Grant profile (draft §4.4) the Resource Authorization Server accepts an
      # ID-JAG as the +assertion+ and exchanges it for an access token.
      class JwtBearer < Doorkeeper::Request::Strategy
        delegate :client, :parameters, to: :server

        def request
          @request ||= Doorkeeper::IdJagGrant::OAuth::JwtAssertionRequest.new(
            Doorkeeper.config,
            client,
            parameters,
          )
        end
      end
    end
  end
end
