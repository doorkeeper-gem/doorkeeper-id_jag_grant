# frozen_string_literal: true

require "spec_helper"
require "generator_spec"
require "generators/doorkeeper/id_jag_grant/install_generator"

RSpec.describe Doorkeeper::IdJagGrant::InstallGenerator do
  include GeneratorSpec::TestCase

  tests described_class
  destination File.expand_path("tmp/dummy", __dir__)

  describe "after running the generator" do
    before do
      prepare_destination
      FileUtils.mkdir(File.expand_path("config", Pathname(destination_root)))
      run_generator
    end

    it "creates an initializer file" do
      assert_file "config/initializers/doorkeeper_id_jag_grant.rb"
    end

    it "copies the locale file" do
      assert_file "config/locales/doorkeeper_id_jag_grant.en.yml"
    end
  end
end
