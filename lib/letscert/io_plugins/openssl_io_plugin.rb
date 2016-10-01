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
module LetsCert

  # OpenSSL IOPlugin
  # @author Sylvain Daubert
  class OpenSSLIOPlugin < IOPlugin

    # @private Regular expression to discriminate PEM
    PEM_RE = /^-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n/m

    # @param [String] name filename
    # @param [:pem,:der] type
    # @raise [ArgumentError] unsupported type
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
