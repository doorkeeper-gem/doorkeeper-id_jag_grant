# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module OAuth
      module IdJag
        # Immutable context passed to the +assertion_encoder+ hook when an
        # IdP Authorization Server issues an ID-JAG through a Token Exchange
        # request (draft §4.3). Gives the hook everything it needs to sign the
        # grant (e.g. select a key) without exposing Doorkeeper internals.
        class TokenExchangeContext
          attr_reader :client, :subject_token, :subject_token_type,
                      :actor_token, :actor_token_type, :audience, :resource,
                      :scopes, :authorization_details, :parameters

          # rubocop:disable Metrics/ParameterLists
          def initialize(client:, subject_token:, subject_token_type:,
                         audience:, resource: nil, scopes: nil,
                         authorization_details: nil, actor_token: nil,
                         actor_token_type: nil, parameters: {})
            @client = client
            @subject_token = subject_token
            @subject_token_type = subject_token_type
            @actor_token = actor_token
            @actor_token_type = actor_token_type
            @audience = audience
            @resource = resource
            @scopes = scopes
            @authorization_details = authorization_details
            @parameters = parameters
          end
          # rubocop:enable Metrics/ParameterLists
        end
      end
    end
  end
end
