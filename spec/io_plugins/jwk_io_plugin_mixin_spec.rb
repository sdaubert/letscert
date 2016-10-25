require_relative '../spec_helper'

module LetsCert

  describe JWKIOPluginMixin do

    class Test; include JWKIOPluginMixin; end

    let(:test) { Test.new }

    it "#load_jwk loads a RSA key from a JSON Web Key raw string" do
      jwk = File.read(File.join(File.dirname(__FILE__), 'test.json'))
      key = test.load_jwk(jwk)

      expect(key).to be_a(OpenSSL::PKey::PKey)
    end

    it "#dump_jwk dumps a RSA key to a JSON Web Key raw string" do
      jwk = File.read(File.join(File.dirname(__FILE__), 'test.json'))
      key = test.load_jwk(jwk)

      jwk2 = test.dump_jwk(key)
      expect(jwk2).to eq(jwk)
    end

    it 'issue 3: #urlsafe_decode64 accepts unpadded base64 string' do
      # Ruby < 2.3: Base64.urlsafe_decode64 calls Base64.strict_decode64
      # which raises when string is not padded. But JWK uses URL safe base64
      # encoding without padding!
      # So JWKIOPluginMixin#urlsafe_decode64 should add padding before calling
      # Base64.urlsafe_decode64
      str = test.urlsafe_encode64('a')
      expect { test.urlsafe_decode64(str) }.to_not raise_error
      expect(test.urlsafe_decode64(str)).to eq('a')
    end
  end

end
