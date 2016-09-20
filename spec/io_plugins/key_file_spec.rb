require_relative '../spec_helper'

module LetsCert

  describe KeyFile do

    let(:keypem) { IOPlugin.registered['key.pem'] }
    let(:keyder) { IOPlugin.registered['key.der'] }

    it 'persist key' do
      expect(keypem.persisted[:key]).to be(true)
      expect(keyder.persisted[:key]).to be(true)
    end

    it '#load private key from key.pem file' do
      change_dir_to File.dirname(__FILE__) do
        data = keypem.load
        expect(data[:key]).to be_a(OpenSSL::PKey::RSA)
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0x00C624BFE15EA0F66560CF7CE38ADDE3F4481BBF90C7C407ACAF111F0470DFB62FC6087941B2A5F44FEEBE709450AC7CDC6B1DEDC246839235965AA04653ECDA31))
      end
    end

    it '#save private key to key.pem file' do
      data = { key: OpenSSL::PKey::RSA.new(512) }
      keypem.save data
      ensure_file_is_deleted('key.pem') do
        expect(File.exist? 'key.pem').to be(true)
        data2 = keypem.load
        expect(data2[:key].params['d'].to_i).to eq(data[:key].params['d'].to_i)
      end
    end

    it '#load private key from key.der file' do
      change_dir_to File.dirname(__FILE__) do
        data = keyder.load
        expect(data[:key]).to be_a(OpenSSL::PKey::RSA)
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0x00C624BFE15EA0F66560CF7CE38ADDE3F4481BBF90C7C407ACAF111F0470DFB62FC6087941B2A5F44FEEBE709450AC7CDC6B1DEDC246839235965AA04653ECDA31))
      end
    end

    it '#save private key to key.der file' do
      data = { key: OpenSSL::PKey::RSA.new(512) }
      keyder.save data
      ensure_file_is_deleted('key.der') do
        expect(File.exist? 'key.der').to be(true)
        data2 = keyder.load
        expect(data2[:key].params['d'].to_i).to eq(data[:key].params['d'].to_i)
      end
    end
  end

end
