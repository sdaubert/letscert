require 'simplecov'
SimpleCov.start do
  add_filter "/spec/"
end

$:.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'letscert'

require 'vcr'
require 'faraday'

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into :faraday
end


# Faraday Middleware to remove HTTP-01 challenge
class RemoveHttp01Middleware < Faraday::Middleware
  def call(request_env)
    @app.call(request_env).on_complete do |response_env|
      body = response_env.response.body
      if body['challenges'] and !body['challenges'].empty?
        body['challenges'].each_with_index do |challenge, index|
          if challenge['type'] == 'http-01'
            body['challenges'].delete_at(index)
            break
          end
        end
      end
    end
  end
end
