require_relative '../spec_helper'

module LetsCert

  describe CertFile do

    let(:certpem) { IOPlugin.registered['cert.pem'] }
    let(:certder) { IOPlugin.registered['cert.der'] }

    it 'persist cert' do
      expect(certpem.persisted[:cert]).to be(true)
      expect(certder.persisted[:cert]).to be(true)
    end

    it '#load cert from cert.pem' do
      change_dir_to File.dirname(__FILE__) do
        data = certpem.load
        expect(data[:cert]).to_not be_nil
        expect(data[:cert]).to be_a(OpenSSL::X509::Certificate)
      end
    end

    it '#load cert from cert.der' do
      change_dir_to File.dirname(__FILE__) do
        data = certder.load
        expect(data[:cert]).to_not be_nil
        expect(data[:cert]).to be_a(OpenSSL::X509::Certificate)
      end
    end

    it '#save cert to cert.pem' do
      data = nil

      change_dir_to File.dirname(__FILE__) do
        data = certpem.load
        expect(data[:cert]).to_not be_nil
      end

      certpem.save data

      ensure_file_is_deleted('cert.pem') do
        expect(File.exist? 'cert.pem').to be(true)
        data2 = certpem.load
        expect(data2[:cert].to_pem).to eq(data[:cert].to_pem)
      end
    end

    it '#save cert to cert.der' do
      data = nil

      change_dir_to File.dirname(__FILE__) do
        data = certder.load
        expect(data[:cert]).to_not be_nil
      end

      certder.save data

      ensure_file_is_deleted('cert.der') do
        expect(File.exist? 'cert.der').to be(true)
        data2 = certder.load
        expect(data2[:cert].to_pem).to eq(data[:cert].to_pem)
      end
    end
  end

end
