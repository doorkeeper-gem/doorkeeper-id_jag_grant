# frozen_string_literal: true

require "spec_helper"

RSpec.describe Doorkeeper::IdJagGrant::OAuth::IdJag::Claims do
  subject(:claims) do
    described_class.new(
      issuer: "https://idp.example/",
      subject: "user-42",
      audience: "https://chat.example/",
      client_id: "abc123",
      resource: "https://api.chat.example/",
      scope: "read write",
      expires_in: 300,
    )
  end

  describe "#header" do
    it "declares the typed JWT header required by the draft (§3.1)" do
      expect(claims.header).to eq("typ" => "oauth-id-jag+jwt")
    end
  end

  describe "#payload" do
    let(:now) { Time.utc(2026, 1, 1, 12, 0, 0) }
    let(:payload) { claims.payload(now: now) }

    it "includes the required claims" do
      expect(payload).to include(
        "iss" => "https://idp.example/",
        "sub" => "user-42",
        "aud" => "https://chat.example/",
        "client_id" => "abc123",
        "iat" => now.to_i,
        "exp" => now.to_i + 300,
      )
      expect(payload["jti"]).to be_present
    end

    it "includes optional resource and scope when present" do
      expect(payload["resource"]).to eq("https://api.chat.example/")
      expect(payload["scope"]).to eq("read write")
    end

    it "omits optional claims that are blank" do
      minimal = described_class.new(
        issuer: "https://idp.example/",
        subject: "user-42",
        audience: "https://chat.example/",
        client_id: "abc123",
      )

      expect(minimal.payload).not_to have_key("resource")
      expect(minimal.payload).not_to have_key("scope")
      expect(minimal.payload).not_to have_key("authorization_details")
    end

    it "merges extra claims (with stringified keys) last" do
      enriched = described_class.new(
        issuer: "https://idp.example/",
        subject: "user-42",
        audience: "https://chat.example/",
        client_id: "abc123",
        extra_claims: { email: "u@example.com", sub: "overridden" },
      )

      payload = enriched.payload
      expect(payload["email"]).to eq("u@example.com")
      expect(payload["sub"]).to eq("overridden")
    end
  end
end
