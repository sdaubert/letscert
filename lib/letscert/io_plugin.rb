module LetsCert

  # Input/output plugin
  class IOPlugin

    # Plugin name
    # @return [String]
    attr_reader :name

    # Allowed plugin names
    ALLOWED_PLUGINS = %w(account_key.json cert.der cert.pem chain.pem full.pem) +
                      %w(fullchain.pem key.der key.pem)

    EMPTY_DATA = { account_key: nil, key: nil, cert: nil, chain: nil }

    @@registered = {}

    # Register a plugin
    def self.register(klass, name)
      plugin = klass.new(name)
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
      @@loger = logger
    end

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


  # {IOPlugin} which read/saves files on disk.
  class FileIOPlugin < IOPlugin

    def load
      @@loger.debug { "Loading #@name" }

      begin
        content = File.read(@name)
      rescue SystemCallError => ex
        if ex.is_a? Errno::ENOENT
          return EMPTY_DATA
        end
        raise
      end

      load_from_content(content)
    end

    # @abstract
    def load_from_content(content)
      raise NotImplementedError
    end

    def save_to_file(data)
      @@logger.info { "saving #@name" }
    end

  end


  # Mixin for IOPlugin subclasses
  module JWKIOPlugin
    def load_jwk(data)
    end

    def dump_jwk(jwk)
    end
  end


  # Account key IO plugin
  class AccountKey < FileIOPlugin
    extend JWKIOPlugin

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

end
