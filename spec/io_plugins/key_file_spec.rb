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
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0x573C8C0EADCBA5E571CD57FAB4D9FE6AC9DC5F9ADF8FEC48667D836B6A0EA9E1240D2A5861258A7E6E5EA1052AFAD71176A49E90BA80F43C44F2BD415161C1E71AA37E7C2BE5C7C18CF964A5A7100C801F558C7B7825D082FEF79A76963786D8CDFE1058F7F178869A09F5377F51DD45EA05B428F41F09C9F29D37BB539512C5))
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
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0x648C2A57083D12CA32A89538DD1AD7BAC5C522E682F0AFD9C834BB44CC536A57880F24D9D8987A0FC2CEF5C8F7A9BA70223E3C3E06229C815955FCE06F198175))
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
