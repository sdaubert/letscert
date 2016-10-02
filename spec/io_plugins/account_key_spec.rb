require_relative '../spec_helper'

module LetsCert

  describe AccountKey do

    before(:all) { IOPlugin.logger = Logger.new('/dev/null') }
    let(:ak) { IOPlugin.registered['account_key.json'] }

    it 'persist account_key' do
      persisted = ak.persisted
      expect(persisted[:account_key]).to be(true)
    end

    it "#load account key from account_key.json file" do
      expect(ak).to be_a(AccountKey)

      change_dir_to File.dirname(__FILE__) do
        content = ak.load
        expect(content).to be_a(Hash)
        expect(content.keys.size).to eq(1)
        expect(content[:account_key]).to be_a(OpenSSL::PKey::PKey)
      end
    end

    it "#save account key to account_key.json file" do
      data = { account_key: OpenSSL::PKey::RSA.new(1024) }
      ak.save(data)
      ensure_file_is_deleted('account_key.json') do
        expect(File.exist?('account_key.json')).to be_truthy
      end
    end

  end

end
