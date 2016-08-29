module LetsCert

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
end
