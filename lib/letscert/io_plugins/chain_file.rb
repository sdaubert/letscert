module LetsCert

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
end
