module LetsCert

  # Input/output plugin
  class IOPlugin

    # Plugin name
    # @return [String]
    attr_reader :name

    # Allowed plugin names
    ALLOWED_PLUGINS = %w(account_key.json cert.der cert.pem chain.pem full.pem) +
                      %w(fullchain.pem key.der key.pem)


    @@registered = {}

    # Get empty data
    def self.empty_data
      { account_key: nil, key: nil, cert: nil, chain: nil }
    end

    # Register a plugin
    def self.register(klass, *args)
      plugin = klass.new(*args)
      if plugin.name =~ /[\/\\]/ or ['.', '..'].include?(plugin.name)
        raise Error, "plugin name should just ne a file name, without path"
      end

      @@registered[plugin.name] = plugin

      klass
    end

    # Get registered plugins
    def self.registered
      @@registered
    end

    # Set logger
    def self.logger=(logger)
      @@logger = logger
    end

    # @param [String] name
    def initialize(name)
      @name = name
    end

    # Get logger instance
    # @return [Logger]
    def logger
      @logger ||= self.class.class_variable_get(:@@logger)
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
  module FileIOPluginMixin

    # Load data from file named {#name}
    # @return [Hash]
    def load
      logger.debug { "Loading #@name" }

      begin
        content = File.read(@name)
      rescue SystemCallError => ex
        if ex.is_a? Errno::ENOENT
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
      @@logger.info { "saving #@name" }
    end

  end


  # Mixin for IOPlugin subclasses that handle JWK
  module JWKIOPluginMixin
    def load_jwk(data)
    end

    def dump_jwk(jwk)
    end
  end


  # Account key IO plugin
  class AccountKey < IOPlugin
    include FileIOPluginMixin
    include JWKIOPluginMixin

    def persisted
      { account_key: true }
    end

    def load_from_content(content)
      { account_key: load_jwk(content) }
    end

    def save(data)
      save_to_file(dump_jwk(data[:account_key]))
    end

  end
  IOPlugin.register(AccountKey, 'account_key.json')


  # OpenSSL IOPlugin
  class OpenSSLIOPlugin < IOPlugin

    def initialize(name, type)
      @type = type
      super(name)
    end

    def load_key(data)
      OpenSSL::PKey::RSA.new data
    end

    def dump_key
    end

    def load_cert(data)
      OpenSSL::X509::Certificate.new data
    end

    def dump_cert(data)
    end
  end


  # Key file plugin
  class KeyFile < OpenSSLIOPlugin
    include FileIOPluginMixin

    def persisted
      @persisted ||= { key: true }
    end

  end
  IOPlugin.register(KeyFile, 'key.pem', :pem)
  IOPlugin.register(KeyFile, 'key.der', :der)


  # Chain file plugin
  class ChainFile < OpenSSLIOPlugin
    include FileIOPluginMixin

    def persisted
      @persisted ||= { chain: true }
    end

  end
  IOPlugin.register(ChainFile, 'chain.pem', :pem)


  # Fullchain file plugin
  class FullChainFile < ChainFile

    def persisted
      @persisted ||= { cert: true, chain: true }
    end

  end
  IOPlugin.register(FullChainFile, 'fullchain.pem', :pem)


  # Cert file plugin
  class CertFile < OpenSSLIOPlugin
    include FileIOPluginMixin

    def persisted
      @persisted ||= { cert: true }
    end

    def load_from_content(content)
      { cert: load_cert(content) }
    end

    def save(data)
      save_to_file(dump_cert(data[:cert]))
    end

  end
  IOPlugin.register(CertFile, 'cert.pem', :pem)
  IOPlugin.register(CertFile, 'cert.der', :der)

end
