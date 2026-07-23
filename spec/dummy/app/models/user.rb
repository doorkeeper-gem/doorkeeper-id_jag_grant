# frozen_string_literal: true

class ApplicationRecord < ::ActiveRecord::Base
  self.abstract_class = true
end

class User < ApplicationRecord
  def self.authenticate!(name, password)
    User.find_by(name: name, password: password)
  end
end
