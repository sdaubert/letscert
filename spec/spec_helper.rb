require 'simplecov'
SimpleCov.start do
  add_filter "/spec/"
end

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'letscert'

require 'vcr'
require 'faraday'
require 'fileutils'

Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}

RSpec.configure do |c|
  c.include HttpHelper
  c.include FileHelper
  c.include CertificateHelper
  c.include JwkHelper
end

VCR.configure do |config|
  config.cassette_library_dir = "spec/cassettes"
  config.hook_into :faraday
end


RSpec::Matchers.define :exit_with_code do |exp_code|
  supports_block_expectations

  actual = nil
  match do |block|
    begin
      block.call
    rescue SystemExit => e
      actual = e.status
    end
    actual and actual == exp_code
  end

  failure_message do |_block|
    "expected block to call exit(#{exp_code}) but exit" +
      (actual.nil? ? " not called" : "(#{actual}) was called")
  end

  failure_message_when_negated do |_block|
    "expected block not to call exit(#{exp_code})"
  end

  description do
    "expect block to call exit(#{exp_code})"
  end
end

def add_option(option, value=nil)
  dash = option.size == 1 ? '-' : '--'
  ARGV << "#{dash}#{option}"
  ARGV << value.to_s unless value.nil?
end
