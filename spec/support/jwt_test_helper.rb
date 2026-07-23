# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "jwt"

# JWT helpers for the test suite.
#
# The built-in ID-JAG verifier requires asymmetric signatures (RS256/ES256/
# PS256), so +rsa_key+ / +encode_id_jag+ mint real RS256-signed assertions.
# The HMAC helpers (+encode_jwt+ / +decode_jwt+) remain for exercising the
# optional custom +assertion_decoder+ path without asymmetric keys.
module JwtTestHelper
  SIGNING_KEY = "id-jag-test-signing-key"

  # A stable RSA keypair for the suite (generated once).
  def rsa_key
    JwtTestHelper.rsa_key
  end

  def self.rsa_key
    @rsa_key ||= OpenSSL::PKey::RSA.generate(2048)
  end

  # Encode an ID-JAG as an RS256-signed JWT with the required `typ` header.
  def encode_id_jag(payload, key: rsa_key, kid: "test-kid", typ: "oauth-id-jag+jwt")
    JWT.encode(payload, key, "RS256", { typ: typ, kid: kid })
  end

  # ---- HMAC helpers (for the custom assertion_decoder path) ----

  def base64url(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end

  def base64url_decode(str)
    Base64.urlsafe_decode64(str + ("=" * ((4 - (str.length % 4)) % 4)))
  end

  def encode_jwt(header, payload)
    segments = [base64url(header.to_json), base64url(payload.to_json)]
    signature = OpenSSL::HMAC.digest("SHA256", SIGNING_KEY, segments.join("."))
    (segments << base64url(signature)).join(".")
  end

  def decode_jwt(token)
    header_b64, payload_b64, signature_b64 = token.split(".")
    expected = OpenSSL::HMAC.digest("SHA256", SIGNING_KEY, "#{header_b64}.#{payload_b64}")
    raise "bad signature" unless secure_compare(base64url_decode(signature_b64.to_s), expected)

    header = JSON.parse(base64url_decode(header_b64))
    payload = JSON.parse(base64url_decode(payload_b64))
    payload.merge("typ" => header["typ"])
  end

  def secure_compare(left, right)
    return false unless left.bytesize == right.bytesize

    OpenSSL.fixed_length_secure_compare(left, right)
  rescue StandardError
    left == right
  end
end

RSpec.configure do |config|
  config.include JwtTestHelper
end
