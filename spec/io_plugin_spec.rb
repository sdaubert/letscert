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

  describe KeyFile do

    let(:keypem) { IOPlugin.registered['key.pem'] }
    let(:keyder) { IOPlugin.registered['key.der'] }

    it 'persist key' do
      expect(keypem.persisted[:key]).to be(true)
      expect(keyder.persisted[:key]).to be(true)
    end

    it '#load private key from key.pem file' do
      pending
      raise
    end

    it '#save private key to key.pem file' do
      pending
      raise
    end

    it '#load private key from key.der file' do
      pending
      raise
    end

    it '#save private key to key.der file' do
      pending
      raise
    end
  end

  describe ChainFile do
    let(:chain) { IOPlugin.registered['chain.pem'] }

    it 'persist chain' do
      expect(chain.persisted[:chain]).to be(true)
    end

  end

  describe FullChainFile do
    let(:fullchain) { IOPlugin.registered['fullchain.pem'] }

    it 'persist chain' do
      expect(fullchain.persisted[:chain]).to be(true)
    end

    it 'persist cert' do
      expect(fullchain.persisted[:cert]).to be(true)
    end

    it '#load cert and chain from fullchain.pem file' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = fullchain.load
        expect(data[:cert]).to_not be_nil
        expect(data[:cert]).to be_a(OpenSSL::X509::Certificate)
        expect(data[:chain]).to_not be_nil
        expect(data[:chain]).to be_a(Array)
        expect(data[:chain].first).to be_a(OpenSSL::X509::Certificate)
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end
    end

    it '#save cert and chain to fullchain.pem file' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = fullchain.load
        expect(data[:cert]).to_not be_nil
        expect(data[:chain]).to_not be_nil
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end

      fullchain.save data

      begin
        expect(File.exist? 'fullchain.pem').to be(true)

        data2 = fullchain.load
        expect(data2[:cert].to_pem).to eq(data[:cert].to_pem)
        data2[:chain].each_with_index do |cert, i|
          expect(cert.to_pem).to eq(data[:chain][i].to_pem)
        end
      rescue Exception
        raise
      ensure
        File.unlink 'fullchain.pem'
      end
    end

  end

  describe CertFile do
  end

end
