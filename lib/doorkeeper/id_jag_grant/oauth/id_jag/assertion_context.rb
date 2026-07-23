# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module OAuth
      module IdJag
        # Immutable context passed to the +assertion_decoder+ hook when a
        # Resource Authorization Server redeems an ID-JAG for an access token
        # through a JWT Bearer request (draft §4.4). The hook is responsible for
        # verifying the signature and issuer trust relationship; Doorkeeper
        # applies the remaining §4.4.1 processing rules on the returned claims.
        class AssertionContext
          attr_reader :client, :assertion, :parameters

          def initialize(client:, assertion:, parameters: {})
            @client = client
            @assertion = assertion
            @parameters = parameters
          end
        end
      end
    end
  end
end
