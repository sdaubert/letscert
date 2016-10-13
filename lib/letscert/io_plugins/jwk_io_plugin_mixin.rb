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
require 'base64'

module LetsCert

  # Mixin for IOPlugin subclasses that handle JWK
  # @author Sylvain Daubert
  module JWKIOPluginMixin

    # Encode string +data+ to base64
    # @param [String] data
    # @return [String]
    def urlsafe_encode64(data)
      Base64.urlsafe_encode64(data).sub(/[\s=]*\z/, '')
    end

    # Decode base64 string +data+
    # @param [String] data
    # @return [String]
    def urlsafe_decode64(data)
      # Ruby < 2.3.0 urlsafe_decode64 use struct_decode64. So the string
      # is rejected if padding is removed (which JWK do)
      # So, we have to reinject padding
      if !data.end_with?('=') && (data.length % 4).nonzero?
        data = data.ljust((data.length + 3) & ~3, '=')
      end
      Base64.urlsafe_decode64(data)
    end

    # Load crypto data from JSON-encoded file
    # @param [String] data JSON-encoded data
    # @return [OpenSSL::PKey::PKey,nil]
    # @raise [Error] unsupported key type
    def load_jwk(data)
      return nil if data.empty?

      h = JSON.parse(data)
      case h['kty']
      when 'RSA'
        pkey = OpenSSL::PKey::RSA.new
        %w(e n d p q).collect do |key|
          next if h[key].nil?
          value = OpenSSL::BN.new(urlsafe_decode64(h[key]), 2)
          pkey.send "#{key}=".to_sym, value
        end
      else
        raise Error, "unknown account key type '#{k['kty']}'"
      end

      pkey
    end

    # Dump crypto data (key) to a JSON-encoded string
    # @param [OpenSSL::PKey] key
    # @return [String]
    # @raise [Error] unsupported key type
    def dump_jwk(key)
      h = {}
      return h.to_json if key.nil?

      case key
      when OpenSSL::PKey::RSA
        h['kty'] = 'RSA'
        h['e'] = urlsafe_encode64(key.e.to_s(2)) if key.e
        h['n'] = urlsafe_encode64(key.n.to_s(2)) if key.n
        if key.private?
          h['d'] = urlsafe_encode64(key.d.to_s(2))
          h['p'] = urlsafe_encode64(key.p.to_s(2))
          h['q'] = urlsafe_encode64(key.q.to_s(2))
        end
      else
        raise Error, 'only RSA keys are supported'
      end
      h.to_json
    end
  end

end
