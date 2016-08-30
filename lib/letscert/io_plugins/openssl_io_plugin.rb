module LetsCert

  # OpenSSL IOPlugin
  # @author Sylvain Daubert
  class OpenSSLIOPlugin < IOPlugin

    # @private Regular expression to discriminate PEM
    PEM_RE = /^-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n/m

    # @param [String] name filename
    # @param [:pem,:der] type
    def initialize(name, type)
      case type
      when :pem
      when :der
      else
        raise ArgumentError, 'type should be :pem or :der'
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
    alias dump_cert dump_key

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
      my_data = data
      m = my_data.match(PEM_RE)
      while m
        yield m[0]
        my_data = my_data[m.end(0)..-1]
        m = my_data.match(PEM_RE)
      end
    end

  end

end
