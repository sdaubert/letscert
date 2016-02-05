# The MIT License (MIT)
#
# Copyright (c) 2016 Sylvain Daubert
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
require 'json'
require 'base64'
require_relative 'loggable'

module LetsCert

  # Input/output plugin
  # @author Sylvain Daubert
  class IOPlugin
    include Loggable

    # Plugin name
    # @return [String]
    attr_reader :name

    # Allowed plugin names
    ALLOWED_PLUGINS = %w(account_key.json cert.der cert.pem chain.pem full.pem) +
                      %w(fullchain.pem key.der key.pem)


    # Registered plugins
    @@registered = {}

    # Get empty data
    # @return [Hash] +{ account_key: nil, key: nil, cert: nil, chain: nil }+
    def self.empty_data
      { account_key: nil, key: nil, cert: nil, chain: nil }
    end

    # Register a plugin
    # @param [Class] klass
    # @param [Array] args args to pass to +klass+ constructor
    # @return [IOPlugin]
    def self.register(klass, *args)
      plugin = klass.new(*args)
      if plugin.name =~ /[\/\\]/ or ['.', '..'].include?(plugin.name)
        raise Error, "plugin name should just be a file name, without path"
      end

      @@registered[plugin.name] = plugin

      klass
    end

    # Get registered plugins
    # @return [Hash] keys are filenames and keys are instances of IOPlugin subclasses.
    def self.registered
      @@registered
    end

    # @param [String] name
    def initialize(name)
      @name = name
    end

    # @abstract This method must be overriden in subclasses
    def load
      raise NotImplementedError
    end

    # @abstract This method must be overriden in subclasses
    def save
      raise NotImplementedError
    end

  end


  # Mixin for IOPmugin subclasses that handle files
  # @author Sylvain Daubert
  module FileIOPluginMixin

    # Load data from file named {#name}
    # @return [Hash]
    def load
      logger.debug { "Loading #@name" }

      begin
        content = File.read(@name)
      rescue SystemCallError => ex
        if ex.is_a? Errno::ENOENT
          logger.info { "no #@name file" }
          return self.class.empty_data
        end
        raise
      end

      load_from_content(content)
    end

    # @abstract
    # @return [Hash]
    def load_from_content(content)
      raise NotImplementedError
    end

    # Save data to file {#name}
    # @param [Hash] data
    # @return [void]
    def save_to_file(data)
      return if data.nil?

      logger.info { "saving #@name" }
      begin
        File.open(name, 'w') do |f|
          f.write(data)
        end
      rescue Errno => ex
        @logger.error { ex.message }
        raise Error, "Error when saving #@name"
      end
    end

  end


  # Mixin for IOPlugin subclasses that handle JWK
  # @author Sylvain Daubert
  module JWKIOPluginMixin

    # Load crypto data from JSON-encoded file
    # @param [String] data JSON-encoded data
    # @return [Hash]
    def load_jwk(data)
      return nil if data.empty?

      hsh = JSON.parse(data)

      key = OpenSSL::PKey::RSA.new
      key.n = OpenSSL::BN.new(Base64.strict_decode64(hsh['n']))
      key.e = OpenSSL::BN.new(Base64.strict_decode64(hsh['e']))
      key.d = OpenSSL::BN.new(Base64.strict_decode64(hsh['e']))
      key.p = OpenSSL::BN.new(Base64.strict_decode64(hsh['p']))
      key.q = OpenSSL::BN.new(Base64.strict_decode64(hsh['q']))
      key.dmp1 = OpenSSL::BN.new(Base64.strict_decode64(hsh['dp']))
      key.dmq1 = OpenSSL::BN.new(Base64.strict_decode64(hsh['dq']))
      key.iqmp = OpenSSL::BN.new(Base64.strict_decode64(hsh['qi']))

      key
    end

    # Dump crypto data (key) to a JSON-encoded string
    # @param [OpenSSL::PKey] jwk
    # @return [String]
    def dump_jwk(jwk)
      hsh = jwk.params

      # Add and rename some fields to be compatible with simp_le
      hsh['kty'] = 'RSA'
      hsh['qi'] = hsh['iqmp'].dup
      hsh['dp'] = hsh['dmp1'].dup
      hsh['dq'] = hsh['dmq1'].dup
      hsh.delete('iqmp')
      hsh.delete('dmpl')
      hsh.delete('dmql')
      hsh.rehash

      hsh.each_key do |key|
        if hsh[key].is_a?(OpenSSL::BN)
          hsh[key] = Base64.strict_encode64(hsh[key].to_s)
        end
      end
      hsh.to_json
    end
  end


  # Account key IO plugin
  # @author Sylvain Daubert
  class AccountKey < IOPlugin
    include FileIOPluginMixin
    include JWKIOPluginMixin

    # @return [Hash] always get +true+ for +:account_key+ key
    def persisted
      { account_key: true }
    end

    # @return [Hash]
    def load_from_content(content)
      { account_key: load_jwk(content) }
    end

    # Save account key.
    # @param [Hash] data
    # @return [void]
    def save(data)
      save_to_file(dump_jwk(data[:account_key]))
    end

  end
  IOPlugin.register(AccountKey, 'account_key.json')


  # OpenSSL IOPlugin
  # @author Sylvain Daubert
  class OpenSSLIOPlugin < IOPlugin

    # @private Regular expression to discriminate PEM
    PEM_RE = /
^-----BEGIN ((?:[\x21-\x2c\x2e-\x7e](?:[- ]?[\x21-\x2c\x2e-\x7e])*)?)\s*-----$
.*?
^-----END \1-----\s*
/x

    # @param [String] name filename
    # @param [:pem,:der] type
    def initialize(name, type)
      case type
      when :pem
      when :der
      else
        raise ArgumentError, "type should be :pem or :der"
      end

      @type = type
      super(name)
    end

    # Load key from raw +data+
    # @param [String] data
    # @return [OpenSSL::PKey]
    def load_key(data)
      OpenSSL::PKey::RSA.new data
    end

    # Dump key/cert data
    # @param [OpenSSL::PKey] key
    # @return [String]
    def dump_key(key)
      case @type
      when :pem
        key.to_pem
      when :der
        key.to_der
      end
    end
    alias :dump_cert :dump_key

    # Load certificate from raw +data+
    # @param [String] data
    # @return [OpenSSL::X509::Certificate]
    def load_cert(data)
      OpenSSL::X509::Certificate.new data
    end


    private

    # Split concatenated PEMs.
    # @param [String] data
    # @yield [String] pem
    def split_pems(data)
      m = data.match(PEM_RE)
      while (m) do
        yield m[0]
        m = [data[m.end(0)..-1]].match(PEM_RE)
      end
    end

  end


  # Key file plugin
  # @author Sylvain Daubert
  class KeyFile < OpenSSLIOPlugin
    include FileIOPluginMixin

    # @return [Hash] always get +true+ for +:key+ key
    def persisted
      @persisted ||= { key: true }
    end

    # @return [Hash]
    def load_from_content(content)
      { key: load_key(content) }
    end

    # Save private key.
    # @param [Hash] data
    # @return [void]
    def save(data)
      save_to_file(dump_key(data[:key]))
    end

  end
  IOPlugin.register(KeyFile, 'key.pem', :pem)
  IOPlugin.register(KeyFile, 'key.der', :der)


  # Chain file plugin
  # @author Sylvain Daubert
  class ChainFile < OpenSSLIOPlugin
    include FileIOPluginMixin

    # @return [Hash] always get +true+ for +:chain+ key
    def persisted
      @persisted ||= { chain: true }
    end

    # @return [Hash]
    def load_from_content(content)
      chain = []
      split_pems(content) do |pem|
        chain << load_cert(pem)
      end
      { chain: chain }
    end

    # Save chain.
    # @param [Hash] data
    # @return [void]
    def save(data)
      save_to_file(data[:chain].map { |c| dump_cert(c) }.join)
    end

  end
  IOPlugin.register(ChainFile, 'chain.pem', :pem)


  # Fullchain file plugin
  # @author Sylvain Daubert
  class FullChainFile < ChainFile

    # @return [Hash] always get +true+ for +:cert+ and +:chain+ keys
    def persisted
      @persisted ||= { cert: true, chain: true }
    end

    # Load full certificate chain
    # @return [Hash]
    def load
      data = super
      if data[:chain].nil? or data[:chain].empty?
        cert, chain = nil, nil
      else
        cert, chain = data[:chain]
      end

      { account_key: data[:account_key], key: data[:key], cert: cert, chain: chain }
    end

    # Save fullchain.
    # @param [Hash] data
    # @return [void]
    def save(data)
      super(account_key: data[:account_key], key: data[:key], cert: nil,
            chain: [data[:cert]] + data[:chain])
    end

  end
  IOPlugin.register(FullChainFile, 'fullchain.pem', :pem)


  # Cert file plugin
  # @author Sylvain Daubert
  class CertFile < OpenSSLIOPlugin
    include FileIOPluginMixin

    # @return [Hash] always get +true+ for +:cert+ key
    def persisted
      @persisted ||= { cert: true }
    end

    # @return [Hash]
    def load_from_content(content)
      { cert: load_cert(content) }
    end

    # Save certificate.
    # @param [Hash] data
    # @return [void]
    def save(data)
      save_to_file(dump_cert(data[:cert]))
    end

  end
  IOPlugin.register(CertFile, 'cert.pem', :pem)
  IOPlugin.register(CertFile, 'cert.der', :der)

end
