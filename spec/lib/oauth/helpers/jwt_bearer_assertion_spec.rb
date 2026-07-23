# frozen_string_literal: true

require "spec_helper"

RSpec.describe Doorkeeper::IdJagGrant::OAuth::Helpers::JwtBearerAssertion do
  let(:issuer) { "https://idp.example/" }
  let(:audience) { "https://rs.example/" }
  let(:rsa_key) { JwtTestHelper.rsa_key }
  let(:client) { double("Client", uid: "client-uid") }

  let(:config) do
    Doorkeeper::IdJagGrant.reset_configuration!
    key = rsa_key
    aud = audience
    iss = issuer
    Doorkeeper::IdJagGrant.configure do
      audience aud
      trusted_issuer(->(i) { i == iss })
      issuer_key(->(_i, _kid) { key.public_key })
      resource_owner_from_assertion(->(_i, sub, _c) { sub })
    end
  end

  def claims(overrides = {})
    now = Time.now.utc.to_i
    {
      "jti" => SecureRandom.hex(8),
      "iss" => issuer,
      "sub" => "user-1",
      "aud" => audience,
      "client_id" => client.uid,
      "iat" => now,
      "exp" => now + 300,
    }.merge(overrides)
  end

  def assertion(overrides = {})
    JWT.encode(claims(overrides), rsa_key, "RS256", { typ: "oauth-id-jag+jwt", kid: "kid-1" })
  end

  def assertion_with(overrides: {}, key: rsa_key, typ: "oauth-id-jag+jwt")
    JWT.encode(claims(overrides), key, "RS256", { typ: typ, kid: "kid-1" })
  end

  describe ".verify" do
    it "returns the claims for a valid assertion" do
      result = described_class.verify(assertion, client: client, config: config)

      expect(result).to be_success
      expect(result.claims).to include("iss" => issuer, "sub" => "user-1", "aud" => audience)
    end

    it "fails when the assertion is blank" do
      expect(described_class.verify("", client: client, config: config)).not_to be_success
    end

    it "fails when the typ header is wrong" do
      result = described_class.verify(assertion_with(typ: "JWT"), client: client, config: config)

      expect(result).not_to be_success
    end

    it "fails when the issuer is not trusted" do
      result = described_class.verify(assertion("iss" => "https://evil.example/"), client: client, config: config)

      expect(result).not_to be_success
    end

    it "fails when the signature is from an unknown key" do
      rogue = OpenSSL::PKey::RSA.generate(2048)
      result = described_class.verify(assertion_with(key: rogue), client: client, config: config)

      expect(result).not_to be_success
    end

    it "fails when the audience does not match" do
      result = described_class.verify(assertion("aud" => "https://other.example/"), client: client, config: config)

      expect(result).not_to be_success
    end

    it "fails when the audience is a multi-valued array" do
      result =
        described_class.verify(assertion("aud" => [audience, "https://other.example/"]), client: client, config: config)

      expect(result).not_to be_success
    end

    it "fails when a required claim is missing" do
      result = described_class.verify(assertion.then do
        JWT.encode(claims.except("jti"), rsa_key, "RS256", { typ: "oauth-id-jag+jwt" })
      end,
                                      client: client, config: config,)

      expect(result).not_to be_success
    end

    it "fails when the client_id does not match the authenticated client" do
      result = described_class.verify(assertion("client_id" => "someone-else"), client: client, config: config)

      expect(result).not_to be_success
    end

    it "fails when the assertion is expired" do
      past = Time.now.utc.to_i - 3600
      result = described_class.verify(assertion("iat" => past, "exp" => past + 60), client: client, config: config)

      expect(result).not_to be_success
    end

    it "rejects an HMAC-signed assertion even if the payload looks valid" do
      hs = JWT.encode(claims, "shared-secret", "HS256", { typ: "oauth-id-jag+jwt", kid: "kid-1" })
      result = described_class.verify(hs, client: client, config: config)

      expect(result).not_to be_success
    end

    context "with a replay store" do
      it "rejects a jti the store has already consumed" do
        Doorkeeper::IdJagGrant.reset_configuration!
        key = rsa_key
        aud = audience
        iss = issuer
        store = double("ReplayStore")
        allow(store).to receive(:consume).and_return(false)
        cfg = Doorkeeper::IdJagGrant.configure do
          audience aud
          trusted_issuer(->(i) { i == iss })
          issuer_key(->(_i, _kid) { key.public_key })
          resource_owner_from_assertion(->(_i, sub, _c) { sub })
          replay_store store
        end

        result = described_class.verify(assertion, client: client, config: cfg)

        expect(result).not_to be_success
      end
    end
  end
end
