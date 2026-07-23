# frozen_string_literal: true

FactoryBot.define do
  factory :application, class: "Doorkeeper::Application" do
    sequence(:name) { |n| "Application #{n}" }
    redirect_uri { "https://app.com/callback" }
    confidential { true }
  end

  factory :access_token, class: "Doorkeeper::AccessToken" do
    application
    expires_in { 2.hours }
  end

  factory :doorkeeper_testing_user, class: "User", aliases: [:resource_owner] do
    sequence(:name) { |n| "User #{n}" }
    password { "sekret" }
  end
end
