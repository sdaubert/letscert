module LetsCert

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
