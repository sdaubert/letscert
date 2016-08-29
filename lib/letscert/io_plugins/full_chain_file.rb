module LetsCert

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
        cert = nil
        chain = []
      else
        cert = data[:chain].shift
        chain = data[:chain]
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
end
