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
end

VCR.configure do |config|
  config.cassette_library_dir = "spec/cassettes"
  config.hook_into :faraday
end


module LetsCert::TEST
  # RSA key length for test.
  # Use minimal key length to speed up tests.
  KEY_LENGTH = 2048

  # URI to ACME test server
  SERVER = 'http://172.17.0.1:4000'
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

# Get a RSA private key.
# Always same key to speed up tests.
def ca_root_key
  @ca_root_key ||= OpenSSL::PKey::RSA.new(LetsCert::TEST::KEY_LENGTH)
end

# Generate a certificate for example.org, signed by #ca_root_key
# @return [cert, domains]
def generate_signed_cert
  unless @generated_signed_cert
    domains = %w(example.org www.example.org)

    key = OpenSSL::PKey::RSA.new(LetsCert::TEST::KEY_LENGTH)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.issuer = OpenSSL::X509::Name.parse "/DC=letscert/CN=CA"
    cert.public_key = key.public_key
    cert.not_before = Time.now
    # 20 days validity
    cert.not_after = cert.not_before + 20 * 24 * 60 * 60
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    domains.each do |domain|
      cert.add_extension(ef.create_extension('subjectAltName',
                                              "DNS:#{domain}",
                                              false))
    end
    cert.sign(ca_root_key, OpenSSL::Digest::SHA256.new)

    @generated_signed_cert = [cert, domains]
  end

  @generated_signed_cert
end
