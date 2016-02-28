$:.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'letscert'

require 'vcr'

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into :faraday
end
