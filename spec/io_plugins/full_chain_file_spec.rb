require_relative '../spec_helper'

module LetsCert

  describe FullChainFile do
    let(:fullchain) { IOPlugin.registered['fullchain.pem'] }

    it 'persist chain' do
      expect(fullchain.persisted[:chain]).to be(true)
    end

    it 'persist cert' do
      expect(fullchain.persisted[:cert]).to be(true)
    end

    it '#load cert and chain from fullchain.pem file' do
      change_dir_to File.dirname(__FILE__) do
        data = fullchain.load
        expect(data[:cert]).to_not be_nil
        expect(data[:cert]).to be_a(OpenSSL::X509::Certificate)
        expect(data[:chain]).to_not be_nil
        expect(data[:chain]).to be_a(Array)
        expect(data[:chain].first).to be_a(OpenSSL::X509::Certificate)
      end
    end

    it '#load from non-existing file initializes chain to empty array' do
      data = fullchain.load
      expect(data[:cert]).to be_nil
      expect(data[:chain]).to be_a(Array)
      expect(data[:chain].size).to eq(0)
    end

    it '#save cert and chain to fullchain.pem file' do
      data = nil

      change_dir_to File.dirname(__FILE__) do
        data = fullchain.load
        expect(data[:cert]).to_not be_nil
        expect(data[:chain]).to_not be_nil
      end

      fullchain.save data

      ensure_file_is_deleted('fullchain.pem') do
        expect(File.exist? 'fullchain.pem').to be(true)

        data2 = fullchain.load
        expect(data2[:cert].to_pem).to eq(data[:cert].to_pem)
        data2[:chain].each_with_index do |cert, i|
          expect(cert.to_pem).to eq(data[:chain][i].to_pem)
        end
      end
    end

  end

end
