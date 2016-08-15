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

    it '.register raises when plugin name contains a path' do
      class NewIO2 < IOPlugin; end
      expect { IOPlugin.register(NewIO2, 'new/io') }.to raise_error(LetsCert::Error)
    end

    it '#load raises NotImplementedError' do
      expect { IOPlugin.new('a').load }.to raise_error(NotImplementedError)
    end

    it '#save raises NotImplementedError' do
      expect { IOPlugin.new('a').save }.to raise_error(NotImplementedError)
    end

  end

  describe FileIOPluginMixin do

    class Test; include FileIOPluginMixin; end

    let(:test) { Test.new}

    it '#load'
    it '#load_from_content raises NotImplementedError' do
      expect { Test.new.load_from_content("a") }.to raise_error(NotImplementedError)
    end

    it '#save_to_file'
    
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
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = keypem.load
        expect(data[:key]).to be_a(OpenSSL::PKey::RSA)
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0x573C8C0EADCBA5E571CD57FAB4D9FE6AC9DC5F9ADF8FEC48667D836B6A0EA9E1240D2A5861258A7E6E5EA1052AFAD71176A49E90BA80F43C44F2BD415161C1E71AA37E7C2BE5C7C18CF964A5A7100C801F558C7B7825D082FEF79A76963786D8CDFE1058F7F178869A09F5377F51DD45EA05B428F41F09C9F29D37BB539512C5))
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end
    end

    it '#save private key to key.pem file' do
      data = { key: OpenSSL::PKey::RSA.new(512) }
      keypem.save data
      begin
        expect(File.exist? 'key.pem').to be(true)

        data2 = keypem.load
        expect(data2[:key].params['d'].to_i).to eq(data[:key].params['d'].to_i)
      rescue Exception
        raise
      ensure
        File.unlink 'key.pem'
      end
    end

    it '#load private key from key.der file' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = keyder.load
        expect(data[:key]).to be_a(OpenSSL::PKey::RSA)
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0x648C2A57083D12CA32A89538DD1AD7BAC5C522E682F0AFD9C834BB44CC536A57880F24D9D8987A0FC2CEF5C8F7A9BA70223E3C3E06229C815955FCE06F198175))
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end
    end

    it '#save private key to key.der file' do
      data = { key: OpenSSL::PKey::RSA.new(512) }
      keyder.save data
      begin
        expect(File.exist? 'key.der').to be(true)

        data2 = keyder.load
        expect(data2[:key].params['d'].to_i).to eq(data[:key].params['d'].to_i)
      rescue Exception
        raise
      ensure
        File.unlink 'key.der'
      end
    end
  end

  describe ChainFile do
    let(:chain) { IOPlugin.registered['chain.pem'] }

    it 'persist chain' do
      expect(chain.persisted[:chain]).to be(true)
    end

    it '#load chain from chain.pem file' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = chain.load
        expect(data[:cert]).to be_nil
        expect(data[:chain]).to_not be_nil
        expect(data[:chain]).to be_a(Array)
        expect(data[:chain].first).to be_a(OpenSSL::X509::Certificate)
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end
    end

    it '#save chain to chain.pem file' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = chain.load
        expect(data[:cert]).to be_nil
        expect(data[:chain]).to_not be_nil
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end

      chain.save data

      begin
        expect(File.exist? 'chain.pem').to be(true)

        data2 = chain.load
        data2[:chain].each_with_index do |cert, i|
          expect(cert.to_pem).to eq(data[:chain][i].to_pem)
        end
      rescue Exception
        raise
      ensure
        File.unlink 'chain.pem'
      end
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

    let(:certpem) { IOPlugin.registered['cert.pem'] }
    let(:certder) { IOPlugin.registered['cert.der'] }

    it 'persist cert' do
      expect(certpem.persisted[:cert]).to be(true)
      expect(certder.persisted[:cert]).to be(true)
    end

    it '#load cert from cert.pem' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = certpem.load
        expect(data[:cert]).to_not be_nil
        expect(data[:cert]).to be_a(OpenSSL::X509::Certificate)
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end
    end

    it '#load cert from cert.der' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = certder.load
        expect(data[:cert]).to_not be_nil
        expect(data[:cert]).to be_a(OpenSSL::X509::Certificate)
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end
    end

    it '#save cert to cert.pem' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = certpem.load
        expect(data[:cert]).to_not be_nil
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end

      certpem.save data

      begin
        expect(File.exist? 'cert.pem').to be(true)

        data2 = certpem.load
        expect(data2[:cert].to_pem).to eq(data[:cert].to_pem)
      rescue Exception
        raise
      ensure
        File.unlink 'cert.pem'
      end
    end

    it '#save cert to cert.der' do
      pwd = FileUtils.pwd
      FileUtils.cd File.dirname(__FILE__)

      begin
        data = certder.load
        expect(data[:cert]).to_not be_nil
      rescue Exception
        raise
      ensure
        FileUtils.cd pwd
      end

      certder.save data

      begin
        expect(File.exist? 'cert.der').to be(true)

        data2 = certder.load
        expect(data2[:cert].to_pem).to eq(data[:cert].to_pem)
      rescue Exception
        raise
      ensure
        File.unlink 'cert.der'
      end
    end
  end

end
