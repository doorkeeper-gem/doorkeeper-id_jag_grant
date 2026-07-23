# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    module OAuth
      # Augments Doorkeeper's RFC 8414 Authorization Server Metadata response
      # with the ID-JAG parameters defined in draft §7:
      #
      #   * +identity_chaining_requested_token_types_supported+ - advertised by
      #     an IdP that can issue an ID-JAG (the token_exchange flow is enabled).
      #   * +authorization_grant_profiles_supported+ - advertised by a Resource
      #     Authorization Server that can process the ID-JAG profile (the
      #     jwt_bearer flow is enabled).
      #
      # Prepended to +Doorkeeper::OAuth::MetadataResponse+ so it can decorate the
      # existing +#body+ without patching core.
      module MetadataResponseExtension
        def body
          # Merge only the ID-JAG keys that apply. Core intentionally keeps some
          # blank entries (e.g. a null userinfo_endpoint), so the base body is
          # not re-filtered here - id_jag_metadata only ever contains present
          # values.
          super.merge(id_jag_metadata)
        end

        private

        def id_jag_metadata
          metadata = {}

          if grant_types_supported.include?(Doorkeeper::IdJagGrant::GRANT_TYPE_TOKEN_EXCHANGE)
            metadata[:identity_chaining_requested_token_types_supported] =
              [Doorkeeper::IdJagGrant::TOKEN_TYPE_ID_JAG]
          end

          if grant_types_supported.include?(Doorkeeper::IdJagGrant::GRANT_TYPE_JWT_BEARER)
            metadata[:authorization_grant_profiles_supported] =
              [Doorkeeper::IdJagGrant::GRANT_PROFILE_ID_JAG]
          end

          metadata
        end
      end
    end
  end
end
