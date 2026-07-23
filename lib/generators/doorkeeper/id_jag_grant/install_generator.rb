# frozen_string_literal: true

require "rails/generators"

module Doorkeeper
  module IdJagGrant
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)
      desc "Installs Doorkeeper Identity Assertion JWT Authorization Grant"

      def install
        template "initializer.rb", "config/initializers/doorkeeper_id_jag_grant.rb"
        copy_file File.expand_path("../../../../config/locales/en.yml", __dir__),
                  "config/locales/doorkeeper_id_jag_grant.en.yml"
      end
    end
  end
end
