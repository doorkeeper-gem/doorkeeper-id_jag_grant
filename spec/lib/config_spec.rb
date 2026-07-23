# frozen_string_literal: true

require "spec_helper"

RSpec.describe Doorkeeper::IdJagGrant::Config do
  before { Doorkeeper::IdJagGrant.reset_configuration! }

  after do
    Doorkeeper::IdJagGrant.reset_configuration!
    Doorkeeper::IdJagGrant.configure {}
  end

  describe ".configuration" do
    it "raises when the extension has not been configured" do
      expect { Doorkeeper::IdJagGrant.configuration }
        .to raise_error(Doorkeeper::IdJagGrant::MissingConfiguration)
    end

    it "returns the built configuration once configured" do
      Doorkeeper::IdJagGrant.configure {}

      expect(Doorkeeper::IdJagGrant.configuration).to be_a(described_class)
    end
  end

  describe ".configured?" do
    it "is false before configuration and true afterwards" do
      expect(Doorkeeper::IdJagGrant.configured?).to be(false)
      Doorkeeper::IdJagGrant.configure {}
      expect(Doorkeeper::IdJagGrant.configured?).to be(true)
    end
  end

  describe "defaults" do
    subject(:config) { Doorkeeper::IdJagGrant.configure {} }

    it "defaults expires_in to 300 seconds" do
      expect(config.expires_in).to eq(300)
    end

    it "defaults the resource owner resolver to the sub claim" do
      expect(config.resolve_resource_owner.call({ "sub" => "user-1" }, nil)).to eq("user-1")
    end

    it "leaves the encoder and decoder unset" do
      expect(config.assertion_encoder).to be_nil
      expect(config.assertion_decoder).to be_nil
    end

    it "leaves the issuer unset" do
      expect(config.issuer).to be_nil
    end

    it "defaults the JWT verifier options for the Resource AS role" do
      expect(config.clock_skew).to eq(60)
      expect(config.allowed_algorithms).to eq(%w[RS256 ES256 PS256])
      expect(config.allow_public_clients).to be(false)
      expect(config.replay_store).to be_nil
    end

    it "fails closed for the required Resource AS hooks" do
      expect(config.trusted_issuer.call("https://idp.example/")).to be(false)
      expect(config.issuer_key.call("https://idp.example/", "kid")).to be_nil
      expect(config.resource_owner_from_assertion.call("iss", "sub", nil)).to be_nil
    end

    it "permits by default via the authorize hook" do
      expect(config.authorize.call(nil, "owner", nil, {})).to be(true)
    end

    it "reports no custom decoder by default" do
      expect(config.custom_assertion_decoder?).to be(false)
    end
  end

  describe "custom options" do
    subject(:config) do
      enc = encoder
      dec = decoder
      res = resolver
      Doorkeeper::IdJagGrant.configure do
        issuer "https://idp.example/"
        expires_in 120
        assertion_encoder(&enc)
        assertion_decoder(&dec)
        resolve_resource_owner(&res)
      end
    end

    let(:encoder) { ->(_claims, _context) { "signed" } }
    let(:decoder) { ->(_assertion, _context) { {} } }
    let(:resolver) { ->(_claims, _client) { "owner" } }

    it "stores the configured values" do
      expect(config.issuer).to eq("https://idp.example/")
      expect(config.expires_in).to eq(120)
      expect(config.assertion_encoder).to eq(encoder)
      expect(config.assertion_decoder).to eq(decoder)
      expect(config.resolve_resource_owner).to eq(resolver)
    end

    it "reports a custom decoder when one is set" do
      expect(config.custom_assertion_decoder?).to be(true)
    end
  end

  describe "Resource AS verifier options" do
    subject(:config) do
      store = replay_store
      Doorkeeper::IdJagGrant.configure do
        audience "https://rs.example/"
        clock_skew 120
        allowed_algorithms %w[ES256]
        allow_public_clients true
        trusted_issuer(->(iss) { iss == "https://idp.example/" })
        issuer_key(->(_iss, _kid) { "PEM" })
        resource_owner_from_assertion(->(_iss, sub, _client) { sub })
        authorize(->(_c, _ro, _s, _cl) { false })
        replay_store store
      end
    end

    let(:replay_store) { double("ReplayStore") }

    it "stores the Resource AS options" do
      expect(config.audience).to eq("https://rs.example/")
      expect(config.audience_value).to eq("https://rs.example/")
      expect(config.clock_skew).to eq(120)
      expect(config.allowed_algorithms).to eq(%w[ES256])
      expect(config.allow_public_clients).to be(true)
      expect(config.trusted_issuer.call("https://idp.example/")).to be(true)
      expect(config.issuer_key.call("https://idp.example/", "kid")).to eq("PEM")
      expect(config.resource_owner_from_assertion.call("iss", "sub", nil)).to eq("sub")
      expect(config.authorize.call(nil, nil, nil, {})).to be(false)
      expect(config.replay_store).to eq(replay_store)
    end
  end

  describe "#audience_value" do
    it "prefers the explicit audience over the issuer" do
      config = Doorkeeper::IdJagGrant.configure do
        issuer "https://idp.example/"
        audience "https://rs.example/"
      end

      expect(config.audience_value).to eq("https://rs.example/")
    end

    it "falls back to issuer_value when audience is unset" do
      config = Doorkeeper::IdJagGrant.configure { issuer "https://idp.example/" }

      expect(config.audience_value).to eq("https://idp.example/")
    end
  end

  describe "#issuer_value" do
    it "uses the ID-JAG issuer when set" do
      config = Doorkeeper::IdJagGrant.configure { issuer "https://idp.example/" }

      expect(config.issuer_value).to eq("https://idp.example/")
    end

    it "falls back to Doorkeeper's core issuer when the ID-JAG issuer is blank" do
      config = Doorkeeper::IdJagGrant.configure {}
      Doorkeeper.configure do
        orm :active_record
        issuer "https://core.example/"
      end

      expect(config.issuer_value).to eq("https://core.example/")
    end

    it "returns nil when neither the ID-JAG nor a core issuer is available" do
      config = Doorkeeper::IdJagGrant.configure {}
      Doorkeeper.configure { orm :active_record }

      expect(config.issuer_value).to be_nil
    end
  end
end
