require_relative 'spec_helper'

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

end
