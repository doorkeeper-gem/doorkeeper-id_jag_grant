# frozen_string_literal: true

require_relative "lib/doorkeeper/id_jag_grant/version"

Gem::Specification.new do |spec|
  spec.name        = "doorkeeper-id_jag_grant"
  spec.version     = Doorkeeper::IdJagGrant::VERSION
  spec.authors     = ["Doorkeeper ID-JAG contributors"]
  spec.email       = ["bulajnikita@gmail.com"]
  spec.homepage    = "https://github.com/doorkeeper-gem/doorkeeper-id_jag_grant"
  spec.summary     = "Identity Assertion JWT Authorization Grant (ID-JAG) extension for Doorkeeper."
  spec.description = <<~DESC
    Adds support for the Identity Assertion JWT Authorization Grant (ID-JAG),
    draft-ietf-oauth-identity-assertion-authz-grant, to Doorkeeper. ID-JAG lets
    an application obtain an access token for a third-party API through a common
    enterprise identity provider, building on RFC 8693 (OAuth 2.0 Token Exchange)
    and RFC 7523 (JWT Bearer grant).
  DESC
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{config,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md", "CHANGELOG.md"]
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "doorkeeper", ">= 6.0.0.beta1"
  spec.add_dependency "jwt", ">= 2.7"

  spec.add_development_dependency "appraisal"
  spec.add_development_dependency "database_cleaner-active_record", "~> 2.0"
  spec.add_development_dependency "factory_bot", "~> 6.0"
  spec.add_development_dependency "rake", ">= 11.3.0"
  spec.add_development_dependency "rspec-rails"
  spec.add_development_dependency "rubocop"
  spec.add_development_dependency "rubocop-rspec"
  spec.add_development_dependency "sqlite3"
end
