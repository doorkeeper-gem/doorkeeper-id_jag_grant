# frozen_string_literal: true

module Doorkeeper
  module IdJagGrant
    # Minimal Rails engine. ID-JAG adds no HTTP endpoints of its own - it plugs
    # into Doorkeeper's existing token endpoint - so this engine only ensures
    # the gem's locale files are added to the Rails i18n load path.
    class Engine < ::Rails::Engine
      isolate_namespace Doorkeeper::IdJagGrant

      config.before_initialize do
        I18n.load_path += Dir[root.join("config", "locales", "*.yml").to_s]
      end
    end
  end
end
