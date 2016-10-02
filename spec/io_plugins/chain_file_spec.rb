require_relative '../spec_helper'

module LetsCert

  describe ChainFile do
    let(:chain) { IOPlugin.registered['chain.pem'] }

    it 'persist chain' do
      expect(chain.persisted[:chain]).to be(true)
    end

    it '#load chain from chain.pem file' do
      change_dir_to File.dirname(__FILE__) do
        data = chain.load
        expect(data[:cert]).to be_nil
        expect(data[:chain]).to_not be_nil
        expect(data[:chain]).to be_a(Array)
        expect(data[:chain].first).to be_a(OpenSSL::X509::Certificate)
      end
    end

    it '#save chain to chain.pem file' do
      data = nil

      change_dir_to File.dirname(__FILE__) do
        data = chain.load
        expect(data[:cert]).to be_nil
        expect(data[:chain]).to_not be_nil
      end

      chain.save data

      ensure_file_is_deleted('chain.pem') do
        expect(File.exist? 'chain.pem').to be(true)
        data2 = chain.load
        data2[:chain].each_with_index do |cert, i|
          expect(cert.to_pem).to eq(data[:chain][i].to_pem)
        end
      end
    end

  end

end
