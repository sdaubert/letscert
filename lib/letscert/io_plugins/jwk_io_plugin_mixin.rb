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
      Base64.urlsafe_decode64(data.sub(/[\s=]*\z/, ''))
    end

    # Load crypto data from JSON-encoded file
    # @param [String] data JSON-encoded data
    # @return [OpenSSL::PKey::PKey]
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
    def dump_jwk(key)
      return {}.to_json if key.nil?

      h = { 'kty' => 'RSA' }
      case key
      when OpenSSL::PKey::RSA
        h['e'] = urlsafe_encode64(key.e.to_s(2)) if key.e
        h['n'] = urlsafe_encode64(key.n.to_s(2)) if key.n
        if key.private?
          h['d'] = urlsafe_encode64(key.d.to_s(2))
          h['p'] = urlsafe_encode64(key.p.to_s(2))
          h['q'] = urlsafe_encode64(key.q.to_s(2))
        end
      else
        raise Error, "only RSA keys are supported"
      end
      h.to_json
    end
  end

end
