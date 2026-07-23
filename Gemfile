# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# Update to ">= 6.0.0" when released
gem "doorkeeper", ">= 6.0.0.beta1"

group :development, :rubocop do
  gem "rubocop", "~> 1.72"
  gem "rubocop-capybara", "~> 3.0", require: false
  gem "rubocop-factory_bot", "~> 2.27", require: false
  gem "rubocop-performance", "~> 1.24", require: false
  gem "rubocop-rails", "~> 2.30", require: false
  gem "rubocop-rspec", "~> 3.5", require: false
  gem "rubocop-rspec_rails", "~> 2.31", require: false
end

group :test do
  gem "rails", ">= 6.1"
end
