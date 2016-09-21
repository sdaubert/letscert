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
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0xad6ccb85b87e57bca59b91af2ebc9c86a56904be5795787d0d2ff18e7edd2cab0dbf90df75ca5e2b65bc57d1ea63e78fe229059fef9e400f842ed313c418dbd6ef83fdbc567cacb08c0a44c47d51796f84ff6f404f20e8031004a715872c79970ebeb808c59a29eefb141820bb8cb8cf0d405d332b1c592b1ffd59211b21a3b0d067d560fcf4932ad452c2126d57865950d64d170cd6a70e04af4d81ff84c572104a542f6c1a975e74879303eab5bdfaff1b940fd2dbed8d8586607ac32df22c32e2047dc8de92e3cb2b133066ed5b98bfa53f6b077ea65fc045f82053f5af44cdecdd1eb9f2d41ddc623583731a70504bffd83258bb9c466c5a9eefd63c4981))
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
        expect(data[:key].params['d']).to eq(OpenSSL::BN.new(0xad6ccb85b87e57bca59b91af2ebc9c86a56904be5795787d0d2ff18e7edd2cab0dbf90df75ca5e2b65bc57d1ea63e78fe229059fef9e400f842ed313c418dbd6ef83fdbc567cacb08c0a44c47d51796f84ff6f404f20e8031004a715872c79970ebeb808c59a29eefb141820bb8cb8cf0d405d332b1c592b1ffd59211b21a3b0d067d560fcf4932ad452c2126d57865950d64d170cd6a70e04af4d81ff84c572104a542f6c1a975e74879303eab5bdfaff1b940fd2dbed8d8586607ac32df22c32e2047dc8de92e3cb2b133066ed5b98bfa53f6b077ea65fc045f82053f5af44cdecdd1eb9f2d41ddc623583731a70504bffd83258bb9c466c5a9eefd63c4981))
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
