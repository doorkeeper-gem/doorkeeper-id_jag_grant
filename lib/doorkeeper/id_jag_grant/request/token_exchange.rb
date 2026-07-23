# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module Request
      # RFC 8693 Token Exchange strategy, scoped to issuing an Identity Assertion
      # JWT Authorization Grant (ID-JAG) as profiled by
      # draft-ietf-oauth-identity-assertion-authz-grant §4.3.
      class TokenExchange < Doorkeeper::Request::Strategy
        delegate :client, :parameters, to: :server

        def request
          @request ||= Doorkeeper::IdJagGrant::OAuth::IdentityAssertionRequest.new(
            Doorkeeper.config,
            client,
            parameters,
          )
        end
      end
    end
  end
end
