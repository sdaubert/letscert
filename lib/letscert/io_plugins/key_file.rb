module LetsCert

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
end
