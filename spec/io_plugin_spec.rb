require_relative 'spec_helper'
require 'fileutils'

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

  describe AccountKey do

    before(:all) { IOPlugin.logger = Logger.new('/dev/null') }

    let(:ak) { IOPlugin.registered['account_key.json'] }

    it 'persist account_key' do
      persisted = ak.persisted
      expect(persisted[:account_key]).to be(true)
    end

    it "#load account key from account_key.json file" do
      expect(ak).to be_a(AccountKey)

      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        content = ak.load
        expect(content).to be_a(Hash)
        expect(content.keys.size).to eq(1)
        expect(content[:account_key]).to be_a(OpenSSL::PKey::PKey)
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end
    end

    it "#save account key to account_key.json file" do
      data = { account_key: OpenSSL::PKey::RSA.new(1024) }
      ak.save(data)
      begin
        expect(File.exist?('account_key.json')).to be_truthy
      rescue Exception
        raise
      ensure
        File.unlink('account_key.json')
      end
    end

  end

end
