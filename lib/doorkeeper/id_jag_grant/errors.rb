# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    # Error classes for the Identity Assertion JWT Authorization Grant (ID-JAG)
    # extension. Kept in the gem's own namespace (rather than reopening
    # +Doorkeeper::Errors+) so no monkey-patching or reflection is needed to
    # define them.
    #
    # +Doorkeeper::Errors::BaseResponseError.name_for_response+ demodulizes the
    # class name (+name.demodulize.underscore.to_sym+), so a namespaced class
    # here still maps to the plain +:unsupported_token_type+ error code
    # Doorkeeper's error response pipeline and the locale file expect.
    module Errors
      # RFC 8693 Token Exchange requesting an unsupported +requested_token_type+.
      class UnsupportedTokenType < Doorkeeper::Errors::BaseResponseError
      end
    end
  end
end
