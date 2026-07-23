# frozen_string_literal: true

require "spec_helper"

# ID-JAG advertises two RFC 8414 metadata parameters (draft §7), added to the
# metadata response by MetadataResponseExtension.
RSpec.describe "Authorization Server Metadata for ID-JAG", type: :request do
  def json_response
    JSON.parse(response.body)
  end

  context "when the token_exchange (IdP) flow is enabled" do
    before do
      Doorkeeper.configure do
        orm :active_record
        grant_flows %w[token_exchange]
      end
    end

    it "advertises the ID-JAG identity chaining requested token type" do
      get "/.well-known/oauth-authorization-server"

      expect(response).to have_http_status(:ok)
      expect(json_response["grant_types_supported"])
        .to include("urn:ietf:params:oauth:grant-type:token-exchange")
      expect(json_response["identity_chaining_requested_token_types_supported"])
        .to eq(["urn:ietf:params:oauth:token-type:id-jag"])
      expect(json_response).not_to have_key("authorization_grant_profiles_supported")
    end
  end

  context "when the jwt_bearer (Resource AS) flow is enabled" do
    before do
      Doorkeeper.configure do
        orm :active_record
        grant_flows %w[jwt_bearer]
      end
    end

    it "advertises the ID-JAG authorization grant profile" do
      get "/.well-known/oauth-authorization-server"

      expect(response).to have_http_status(:ok)
      expect(json_response["grant_types_supported"])
        .to include("urn:ietf:params:oauth:grant-type:jwt-bearer")
      expect(json_response["authorization_grant_profiles_supported"])
        .to eq(["urn:ietf:params:oauth:grant-profile:id-jag"])
      expect(json_response).not_to have_key("identity_chaining_requested_token_types_supported")
    end
  end

  context "when neither ID-JAG flow is enabled" do
    before do
      Doorkeeper.configure do
        orm :active_record
        grant_flows %w[authorization_code client_credentials]
      end
    end

    it "omits both ID-JAG metadata parameters" do
      get "/.well-known/oauth-authorization-server"

      expect(response).to have_http_status(:ok)
      expect(json_response).not_to have_key("identity_chaining_requested_token_types_supported")
      expect(json_response).not_to have_key("authorization_grant_profiles_supported")
    end
  end
end
