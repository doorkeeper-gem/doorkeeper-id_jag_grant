# frozen_string_literal: true

ENV["RAILS_ENV"] ||= "test"

require "bundler/setup"

require File.expand_path("dummy/config/environment", __dir__)
require "rspec/rails"
require "factory_bot"
require "database_cleaner/active_record"

# Load the User model and build the schema into the in-memory database.
require File.expand_path("dummy/app/models/user", __dir__)
load File.expand_path("dummy/db/schema.rb", __dir__)

Dir[File.expand_path("support/**/*.rb", __dir__)].each { |file| require file }

RSpec.configure do |config|
  config.include FactoryBot::Syntax::Methods
  config.include RSpec::Rails::RequestExampleGroup, type: :request

  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.before(:suite) do
    DatabaseCleaner.strategy = :transaction
    DatabaseCleaner.clean_with(:truncation)
    FactoryBot.find_definitions
  end

  config.around do |example|
    DatabaseCleaner.cleaning { example.run }
  end

  # Reset the ID-JAG configuration before each example, then re-apply the
  # default empty configuration so unconfigured examples degrade gracefully
  # (matching the gem's load-time default).
  config.before do
    Doorkeeper::IdJagGrant.reset_configuration!
    Doorkeeper::IdJagGrant.configure {}
  end

  config.order = :random
  Kernel.srand config.seed
end
