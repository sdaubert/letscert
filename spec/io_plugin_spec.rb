require_relative 'spec_helper'

module LetsCert

  describe IOPlugin do

    it '.empty_data always returns the same hash' do
      hsh = IOPlugin.empty_data

      expect(hsh.keys.size).to eq(4)
      [:account_key, :key, :cert, :chain].each do |key|
        expect(hsh.keys).to include(key)
        expect(hsh[key]).to be_nil
      end
    end

    it '.register registers known subclasses' do
      names = %w(account_key.json key.pem key.der chain.pem fullchain.pem)
      names += %w(cert.pem cert.der)

      expect(IOPlugin.registered.size).to eq(names.size)

      names.each do |name|
        expect(IOPlugin.registered.keys).to include(name)
      end
    end

    it '.register may register new classes' do
      class NewIO < IOPlugin;end
      IOPlugin.register(NewIO, 'newio')

      expect(IOPlugin.registered.keys).to include('newio')
      expect(IOPlugin.registered['newio']).to be_a(NewIO)
    end

  end

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
  end

end
