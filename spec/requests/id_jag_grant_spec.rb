# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Identity Assertion JWT Authorization Grant (ID-JAG)", type: :request do
  let(:idp_issuer) { "https://idp.example/" }
  let(:client) { FactoryBot.create(:application, scopes: "read write") }

  def authorization(app)
    credentials = ActionController::HttpAuthentication::Basic.encode_credentials(app.uid, app.secret)
    { "HTTP_AUTHORIZATION" => credentials }
  end

  def json_response
    JSON.parse(response.body)
  end

  # ---------------------------------------------------------------------------
  # Stage 1 - IdP: Token Exchange -> ID-JAG (draft §4.3)
  # ---------------------------------------------------------------------------
  describe "Token Exchange requesting an ID-JAG (IdP role)" do
    let(:subject_id_token) { "the-subject-id-token" }

    before do
      test = self
      issuer_url = idp_issuer
      Doorkeeper.configure do
        orm :active_record
        grant_flows %w[token_exchange]
        default_scopes :read
        optional_scopes :write
      end
      Doorkeeper::IdJagGrant.configure do
        issuer issuer_url
        assertion_encoder(lambda do |claims, _context|
          # A real IdP decodes context.subject_token to resolve the subject;
          # here we just trust the test's canned value.
          payload = claims.payload.merge("sub" => "user-42")
          test.encode_jwt(claims.header, payload)
        end)
      end
    end

    def exchange_params(overrides = {})
      {
        grant_type: Doorkeeper::IdJagGrant::GRANT_TYPE_TOKEN_EXCHANGE,
        requested_token_type: Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_JAG,
        subject_token: subject_id_token,
        subject_token_type: Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_TOKEN,
        audience: "https://chat.example/",
        resource: "https://api.chat.example/",
        scope: "read",
      }.merge(overrides)
    end

    it "issues a signed ID-JAG with the RFC 8693 response shape" do
      post "/oauth/token", params: exchange_params, headers: authorization(client)

      expect(response).to have_http_status(:ok)
      expect(json_response["issued_token_type"]).to eq(Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_JAG)
      expect(json_response["token_type"]).to eq("N_A")
      expect(json_response["expires_in"]).to eq(300)
      expect(json_response["scope"]).to eq("read")

      claims = decode_jwt(json_response["access_token"])
      expect(claims["typ"]).to eq("oauth-id-jag+jwt")
      expect(claims["iss"]).to eq(idp_issuer)
      expect(claims["aud"]).to eq("https://chat.example/")
      expect(claims["client_id"]).to eq(client.uid)
      expect(claims["sub"]).to eq("user-42")
      expect(claims["resource"]).to eq("https://api.chat.example/")
      expect(claims["scope"]).to eq("read")
      expect(claims).to include("jti", "iat", "exp")
    end

    it "rejects an unsupported requested_token_type" do
      post "/oauth/token",
           params: exchange_params(requested_token_type: "urn:ietf:params:oauth:token-type:access_token"),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("unsupported_token_type")
    end

    it "rejects an unsupported subject_token_type" do
      post "/oauth/token",
           params: exchange_params(subject_token_type: "urn:example:bogus"),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_request")
    end

    it "requires the subject_token" do
      post "/oauth/token",
           params: exchange_params.except(:subject_token),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_request")
    end

    it "requires the audience" do
      post "/oauth/token",
           params: exchange_params.except(:audience),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_request")
    end

    it "requires actor_token_type when actor_token is present" do
      post "/oauth/token",
           params: exchange_params(actor_token: "actor-token").except(:actor_token_type),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_request")
    end

    it "accepts JSON authorization_details and echoes the granted value" do
      details = [{ "type" => "chat_read", "actions" => ["read"] }]

      post "/oauth/token",
           params: exchange_params(authorization_details: details.to_json),
           headers: authorization(client)

      expect(response).to have_http_status(:ok)
      expect(json_response["authorization_details"]).to eq(details)
      claims = decode_jwt(json_response["access_token"])
      expect(claims["authorization_details"]).to eq(details)
    end

    it "rejects non-array authorization_details" do
      post "/oauth/token",
           params: exchange_params(authorization_details: "{\"type\":\"chat_read\"}"),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_request")
    end

    it "requires client authentication" do
      post "/oauth/token", params: exchange_params

      expect(response).to have_http_status(:unauthorized)
      expect(json_response["error"]).to eq("invalid_client")
    end

    it "rejects scopes outside those allowed for the client" do
      post "/oauth/token",
           params: exchange_params(scope: "unknown"),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_scope")
    end

    describe "subject token validation (draft §4.3.3)" do
      # Common configuration for the IdP role, extended with validation hooks.
      def configure_idp(*hooks)
        test = self
        issuer_url = idp_issuer
        Doorkeeper.configure do
          orm :active_record
          grant_flows %w[token_exchange]
          default_scopes :read
          optional_scopes :write
        end
        Doorkeeper::IdJagGrant.configure do
          issuer issuer_url
          assertion_encoder(lambda do |claims, _context|
            payload = claims.payload.merge("sub" => "user-42")
            test.encode_jwt(claims.header, payload)
          end)
          hooks.each do |(name, value)|
            public_send(name, value)
          end
        end
      end

      context "with validate_subject_token hook (audience/client binding)" do
        context "when the subject token audience is bound to the client" do
          before do
            configure_idp(
              [:validate_subject_token, ->(_subj, _type, _c) { true }],
            )
          end

          it "allows the exchange" do
            post "/oauth/token", params: exchange_params, headers: authorization(client)

            expect(response).to have_http_status(:ok)
            expect(json_response["issued_token_type"]).to eq(Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_JAG)
          end
        end

        context "when the subject token audience does not match the client" do
          before do
            configure_idp(
              [:validate_subject_token, ->(_subj, _type, _c) { false }],
            )
          end

          it "rejects the exchange with invalid_grant" do
            post "/oauth/token", params: exchange_params, headers: authorization(client)

            expect(response).to have_http_status(:bad_request)
            expect(json_response["error"]).to eq("invalid_grant")
          end
        end

        context "when the hook raises an exception" do
          before do
            configure_idp(
              [:validate_subject_token, ->(_subj, _type, _c) { raise StandardError, "boom" }],
            )
          end

          it "rejects the exchange with invalid_grant" do
            post "/oauth/token", params: exchange_params, headers: authorization(client)

            expect(response).to have_http_status(:bad_request)
            expect(json_response["error"]).to eq("invalid_grant")
          end
        end

        context "when the hook is not configured" do
          before do
            configure_idp
          end

          it "allows the exchange (hook is optional)" do
            post "/oauth/token", params: exchange_params, headers: authorization(client)

            expect(response).to have_http_status(:ok)
          end
        end
      end

      context "with enforce_refresh_token_policy hook" do
        let(:refresh_token_subject) { "the-refresh-token-value" }

        def exchange_refresh_token
          exchange_params(
            subject_token: refresh_token_subject,
            subject_token_type: Doorkeeper::IdJagGrant::TOKEN_TYPE_REFRESH_TOKEN,
          )
        end

        context "when the policy allows the exchange" do
          before do
            configure_idp(
              [:enforce_refresh_token_policy, ->(_subj, _c) { true }],
            )
          end

          it "allows the exchange" do
            post "/oauth/token", params: exchange_refresh_token, headers: authorization(client)

            expect(response).to have_http_status(:ok)
            expect(json_response["issued_token_type"]).to eq(Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_JAG)
          end
        end

        context "when the policy denies the exchange" do
          before do
            configure_idp(
              [:enforce_refresh_token_policy, ->(_subj, _c) { false }],
            )
          end

          it "rejects with invalid_grant" do
            post "/oauth/token", params: exchange_refresh_token, headers: authorization(client)

            expect(response).to have_http_status(:bad_request)
            expect(json_response["error"]).to eq("invalid_grant")
          end
        end

        context "when the hook raises an exception" do
          before do
            configure_idp(
              [:enforce_refresh_token_policy, ->(_subj, _c) { raise StandardError, "boom" }],
            )
          end

          it "rejects with invalid_grant when the policy hook raises an exception" do
            post "/oauth/token", params: exchange_refresh_token, headers: authorization(client)

            expect(response).to have_http_status(:bad_request)
            expect(json_response["error"]).to eq("invalid_grant")
          end
        end

        context "when the subject token is an ID token, not a refresh token" do
          let(:policy_hook) { double("policy_hook") }

          before do
            allow(policy_hook).to receive(:call).and_return(false)
            configure_idp(
              [:enforce_refresh_token_policy, policy_hook],
            )
          end

          it "does not invoke the policy hook (skips for non-refresh tokens)" do
            post "/oauth/token", params: exchange_params, headers: authorization(client)

            expect(response).to have_http_status(:ok)
            expect(policy_hook).not_to have_received(:call)
          end
        end

        context "when the hook is not configured" do
          before do
            configure_idp
          end

          it "allows the refresh-token exchange (hook is optional)" do
            post "/oauth/token", params: exchange_refresh_token, headers: authorization(client)

            expect(response).to have_http_status(:ok)
          end
        end
      end

      context "when both hooks are configured together" do
        before do
          configure_idp(
            [:validate_subject_token, ->(_subj, _type, _c) { true }],
            [:enforce_refresh_token_policy, ->(_subj, _c) { true }],
          )
        end

        it "allows valid exchanges" do
          post "/oauth/token", params: exchange_params, headers: authorization(client)

          expect(response).to have_http_status(:ok)
        end

        it "rejects when the refresh token policy fails" do
          configure_idp(
            [:validate_subject_token, ->(_subj, _type, _c) { true }],
            [:enforce_refresh_token_policy, ->(_subj, _c) { false }],
          )

          params = exchange_params(
            subject_token: "refresh-token",
            subject_token_type: Doorkeeper::IdJagGrant::TOKEN_TYPE_REFRESH_TOKEN,
          )
          post "/oauth/token", params: params, headers: authorization(client)

          expect(response).to have_http_status(:bad_request)
          expect(json_response["error"]).to eq("invalid_grant")
        end
      end
    end

    context "when no encoder is configured" do
      before do
        issuer_url = idp_issuer
        Doorkeeper.configure do
          orm :active_record
          grant_flows %w[token_exchange]
          default_scopes :read
          optional_scopes :write
        end
        Doorkeeper::IdJagGrant.configure do
          issuer issuer_url
        end
      end

      it "rejects the request with invalid_request" do
        post "/oauth/token", params: exchange_params, headers: authorization(client)

        expect(response).to have_http_status(:bad_request)
        expect(json_response["error"]).to eq("invalid_request")
      end
    end

    context "when the assertion_encoder does not set the required 'sub' claim" do
      before do
        test = self
        issuer_url = idp_issuer
        Doorkeeper.configure do
          orm :active_record
          grant_flows %w[token_exchange]
          default_scopes :read
          optional_scopes :write
        end
        Doorkeeper::IdJagGrant.configure do
          issuer issuer_url
          assertion_encoder(lambda do |claims, _context|
            # Deliberately omits `sub` — the post-encode guard must catch this.
            test.encode_jwt(claims.header, claims.payload)
          end)
        end
      end

      it "rejects the request with invalid_request" do
        post "/oauth/token", params: exchange_params, headers: authorization(client)

        expect(response).to have_http_status(:bad_request)
        expect(json_response["error"]).to eq("invalid_request")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Stage 2 - Resource AS: JWT Bearer <- ID-JAG -> access token (draft §4.4)
  #
  # These exercise the built-in JWT verifier (default path): assertions are
  # RS256-signed and verified against the trusted issuer's public key.
  # ---------------------------------------------------------------------------
  describe "JWT Bearer redeeming an ID-JAG (Resource AS role, built-in verifier)" do
    before do
      test = self
      issuer_url = idp_issuer
      Doorkeeper.configure do
        orm :active_record
        grant_flows %w[jwt_bearer]
        default_scopes :read
        optional_scopes :write
      end
      Doorkeeper::IdJagGrant.configure do
        audience issuer_url
        trusted_issuer(->(iss) { iss == issuer_url })
        issuer_key(->(_iss, _kid) { test.rsa_key.public_key })
        resource_owner_from_assertion(->(_iss, sub, _client) { sub })
      end
    end

    def id_jag_claims(overrides = {})
      now = Time.now.utc.to_i
      {
        "jti" => SecureRandom.hex(8),
        "iss" => idp_issuer,
        "sub" => "user-42",
        "aud" => idp_issuer,
        "client_id" => client.uid,
        "iat" => now,
        "exp" => now + 300,
        "scope" => "read",
      }.merge(overrides)
    end

    def id_jag(overrides = {})
      encode_id_jag(id_jag_claims(overrides))
    end

    # For tests that need to override the signing key / typ header.
    def id_jag_with(overrides: {}, key: rsa_key, typ: "oauth-id-jag+jwt")
      encode_id_jag(id_jag_claims(overrides), key: key, typ: typ)
    end

    def bearer_params(assertion)
      {
        grant_type: Doorkeeper::IdJagGrant::GRANT_TYPE_JWT_BEARER,
        assertion: assertion,
      }
    end

    it "issues an access token for the resolved resource owner" do
      expect do
        post "/oauth/token", params: bearer_params(id_jag), headers: authorization(client)
      end.to change(Doorkeeper::AccessToken, :count).by(1)

      expect(response).to have_http_status(:ok)
      token = Doorkeeper::AccessToken.first
      expect(json_response["access_token"]).to eq(token.token)
      expect(json_response["token_type"]).to eq("Bearer")
      expect(json_response["scope"]).to eq("read")
      expect(token.scopes_string).to eq("read")
    end

    it "never issues a refresh token (ID-JAG §4.4.3)" do
      post "/oauth/token", params: bearer_params(id_jag), headers: authorization(client)

      expect(response).to have_http_status(:ok)
      expect(json_response).not_to have_key("refresh_token")
    end

    it "rejects an ID-JAG whose aud does not match this server's audience" do
      post "/oauth/token",
           params: bearer_params(id_jag("aud" => "https://someone-else.example/")),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects an ID-JAG whose aud is a multi-valued array" do
      post "/oauth/token",
           params: bearer_params(id_jag("aud" => [idp_issuer, "https://other.example/"])),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects an ID-JAG whose client_id does not match the authenticated client" do
      other = FactoryBot.create(:application)

      post "/oauth/token",
           params: bearer_params(id_jag("client_id" => other.uid)),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects an assertion whose `typ` header is not oauth-id-jag+jwt" do
      post "/oauth/token",
           params: bearer_params(id_jag_with(typ: "JWT")),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects an assertion signed by an untrusted key" do
      rogue = OpenSSL::PKey::RSA.generate(2048)

      post "/oauth/token",
           params: bearer_params(id_jag_with(key: rogue)),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects an assertion from an untrusted issuer" do
      post "/oauth/token",
           params: bearer_params(id_jag("iss" => "https://evil.example/")),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects an expired assertion" do
      past = Time.now.utc.to_i - 3600
      post "/oauth/token",
           params: bearer_params(id_jag("iat" => past, "exp" => past + 60)),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects an assertion missing a required claim" do
      post "/oauth/token",
           params: bearer_params(id_jag.then { encode_id_jag(id_jag_claims.except("jti")) }),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "accepts an aud claim that is a single-element array" do
      post "/oauth/token",
           params: bearer_params(id_jag("aud" => [idp_issuer])),
           headers: authorization(client)

      expect(response).to have_http_status(:ok)
    end

    it "rejects a tampered / badly signed assertion" do
      post "/oauth/token",
           params: bearer_params("#{id_jag}tampered"),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "requires the assertion parameter" do
      post "/oauth/token",
           params: { grant_type: Doorkeeper::IdJagGrant::GRANT_TYPE_JWT_BEARER },
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_request")
    end

    it "rejects the grant when the resource owner cannot be resolved" do
      issuer_url = idp_issuer
      test = self
      Doorkeeper::IdJagGrant.configure do
        audience issuer_url
        trusted_issuer(->(iss) { iss == issuer_url })
        issuer_key(->(_iss, _kid) { test.rsa_key.public_key })
        resource_owner_from_assertion(->(_iss, _sub, _client) {})
      end

      post "/oauth/token", params: bearer_params(id_jag), headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    context "with the confidential-client restriction (ID-JAG §8.1)" do
      let(:public_client) { FactoryBot.create(:application, confidential: false, scopes: "read write") }

      it "rejects a public client by default" do
        post "/oauth/token",
             params: bearer_params(id_jag("client_id" => public_client.uid)),
             headers: authorization(public_client)

        # `unauthorized_client` maps to 401 on Doorkeeper < 6 and 400 on newer
        # versions (RFC 6749 §5.2); assert on the error code, not the status.
        expect(response).to have_http_status(:bad_request).or have_http_status(:unauthorized)
        expect(json_response["error"]).to eq("unauthorized_client")
      end

      it "allows a public client when allow_public_clients is enabled" do
        issuer_url = idp_issuer
        test = self
        Doorkeeper::IdJagGrant.configure do
          audience issuer_url
          allow_public_clients true
          trusted_issuer(->(iss) { iss == issuer_url })
          issuer_key(->(_iss, _kid) { test.rsa_key.public_key })
          resource_owner_from_assertion(->(_iss, sub, _client) { sub })
        end

        post "/oauth/token",
             params: bearer_params(id_jag("client_id" => public_client.uid)),
             headers: authorization(public_client)

        expect(response).to have_http_status(:ok)
      end
    end

    context "with an authorize policy hook" do
      it "rejects the grant when the policy denies it" do
        issuer_url = idp_issuer
        test = self
        Doorkeeper::IdJagGrant.configure do
          audience issuer_url
          trusted_issuer(->(iss) { iss == issuer_url })
          issuer_key(->(_iss, _kid) { test.rsa_key.public_key })
          resource_owner_from_assertion(->(_iss, sub, _client) { sub })
          authorize(->(_client, _resource_owner, _scopes, _claims) { false })
        end

        post "/oauth/token", params: bearer_params(id_jag), headers: authorization(client)

        expect(response).to have_http_status(:bad_request).or have_http_status(:unauthorized)
        expect(json_response["error"]).to eq("unauthorized_client")
      end
    end

    context "with a replay store" do
      it "rejects a second use of the same jti" do
        seen = []
        store = Object.new
        store.define_singleton_method(:consume) do |jti, _iss, _exp|
          !seen.include?(jti).tap { seen << jti }
        end

        issuer_url = idp_issuer
        test = self
        Doorkeeper::IdJagGrant.configure do
          audience issuer_url
          trusted_issuer(->(iss) { iss == issuer_url })
          issuer_key(->(_iss, _kid) { test.rsa_key.public_key })
          resource_owner_from_assertion(->(_iss, sub, _client) { sub })
          replay_store store
        end

        assertion = id_jag
        post "/oauth/token", params: bearer_params(assertion), headers: authorization(client)
        expect(response).to have_http_status(:ok)

        post "/oauth/token", params: bearer_params(assertion), headers: authorization(client)
        expect(response).to have_http_status(:bad_request)
        expect(json_response["error"]).to eq("invalid_grant")
      end
    end

    context "when the required hooks are not configured (fail closed)" do
      before do
        Doorkeeper::IdJagGrant.reset_configuration!
        Doorkeeper::IdJagGrant.configure { audience "https://idp.example/" }
      end

      it "rejects the request with invalid_grant" do
        post "/oauth/token", params: bearer_params(id_jag), headers: authorization(client)

        expect(response).to have_http_status(:bad_request)
        expect(json_response["error"]).to eq("invalid_grant")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Stage 2 (alternative) - custom assertion_decoder bring-your-own-crypto path
  # ---------------------------------------------------------------------------
  describe "JWT Bearer redeeming an ID-JAG (Resource AS role, custom decoder)" do
    before do
      test = self
      issuer_url = idp_issuer
      Doorkeeper.configure do
        orm :active_record
        grant_flows %w[jwt_bearer]
        default_scopes :read
        optional_scopes :write
      end
      Doorkeeper::IdJagGrant.configure do
        audience issuer_url
        assertion_decoder(->(assertion, _context) { test.decode_jwt(assertion) })
        resolve_resource_owner(->(claims, _client) { claims["sub"] })
      end
    end

    def id_jag(overrides = {})
      now = Time.now.utc.to_i
      payload = {
        "jti" => SecureRandom.hex(8),
        "iss" => idp_issuer,
        "sub" => "user-42",
        "aud" => idp_issuer,
        "client_id" => client.uid,
        "iat" => now,
        "exp" => now + 300,
        "scope" => "read",
      }.merge(overrides).compact
      JWT.encode(payload, JwtTestHelper::SIGNING_KEY, "HS256", { typ: "oauth-id-jag+jwt" })
    end

    def bearer_params(assertion)
      {
        grant_type: Doorkeeper::IdJagGrant::GRANT_TYPE_JWT_BEARER,
        assertion: assertion,
      }
    end

    it "issues an access token using the custom decoder" do
      expect do
        post "/oauth/token", params: bearer_params(id_jag), headers: authorization(client)
      end.to change(Doorkeeper::AccessToken, :count).by(1)

      expect(response).to have_http_status(:ok)
      expect(json_response["scope"]).to eq("read")
    end

    it "still enforces the aud claim on the decoded claims" do
      post "/oauth/token",
           params: bearer_params(id_jag("aud" => "https://someone-else.example/")),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "still enforces client_id continuity on the decoded claims" do
      other = FactoryBot.create(:application)

      post "/oauth/token",
           params: bearer_params(id_jag("client_id" => other.uid)),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects a decoded assertion missing required claims" do
      post "/oauth/token",
           params: bearer_params(id_jag("exp" => nil)),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects a decoded assertion with a multi-valued aud array" do
      post "/oauth/token",
           params: bearer_params(id_jag("aud" => [idp_issuer, "https://other.example/"])),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end

    it "rejects when the custom decoder raises (bad signature)" do
      post "/oauth/token",
           params: bearer_params("#{id_jag}tampered"),
           headers: authorization(client)

      expect(response).to have_http_status(:bad_request)
      expect(json_response["error"]).to eq("invalid_grant")
    end
  end
end
