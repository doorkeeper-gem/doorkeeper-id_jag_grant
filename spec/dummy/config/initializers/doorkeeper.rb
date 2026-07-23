# frozen_string_literal: true

# Baseline Doorkeeper configuration for the dummy app. Individual examples
# reconfigure Doorkeeper (e.g. to enable the token_exchange / jwt_bearer grant
# flows and set the ID-JAG hooks); this initial config is only needed so the
# token endpoint routes are mapped when routes are drawn at boot.
Doorkeeper.configure do
  orm :active_record

  resource_owner_authenticator do
    User.first || User.create!(name: "Default")
  end

  grant_flows %w[authorization_code client_credentials token_exchange jwt_bearer]

  default_scopes :read
  optional_scopes :write
end
