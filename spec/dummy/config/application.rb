# frozen_string_literal: true

require "rails"
require "action_controller/railtie"
require "active_record/railtie"

require "doorkeeper"
require "doorkeeper/id_jag_grant"

module Dummy
  class Application < Rails::Application
    config.root = File.expand_path("..", __dir__)
    config.load_defaults ::Rails::VERSION::STRING.to_f
    config.eager_load = false
    config.secret_key_base = "id-jag-grant-dummy-secret-key-base"
    config.logger = Logger.new(IO::NULL)
    config.log_level = :fatal

    # Resolve config/database.yml relative to this dummy app rather than the
    # process working directory (which is the gem root under `rake spec`).
    config.paths["config/database"] = [File.expand_path("database.yml", __dir__)]

    # Keep the dummy app quiet and minimal.
    config.action_dispatch.show_exceptions = :none if config.action_dispatch.respond_to?(:show_exceptions=)
  end
end
