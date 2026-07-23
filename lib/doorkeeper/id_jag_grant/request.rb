# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module Request
      autoload :TokenExchange, "doorkeeper/id_jag_grant/request/token_exchange"
      autoload :JwtBearer, "doorkeeper/id_jag_grant/request/jwt_bearer"
    end
  end
end
