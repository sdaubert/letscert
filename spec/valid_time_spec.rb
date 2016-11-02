require_relative 'spec_helper'

module LetsCert

  describe ValidTime do

    context '.new' do
      it 'accepts a String' do
        expect(ValidTime.new('1234')).to be_a(ValidTime)
      end

      it 'accepts m modifier' do
        expect(ValidTime.new('1234m')).to be_a(ValidTime)
      end

      it 'accepts h modifier' do
        expect(ValidTime.new('1234h')).to be_a(ValidTime)
      end

      it 'accepts d modifier' do
        expect(ValidTime.new('1234d')).to be_a(ValidTime)
      end

      it 'raises on malformed string' do
        expect { ValidTime.new '1234s' }.to raise_error(OptionParser::InvalidArgument)
        expect { ValidTime.new '1234a' }.to raise_error(OptionParser::InvalidArgument)
        expect { ValidTime.new 'm1234' }.to raise_error(OptionParser::InvalidArgument)
        expect { ValidTime.new '1h2m' }.to raise_error(OptionParser::InvalidArgument)
      end
    end

    context '#to_seconds' do
      it 'returns time as seconds' do
        expect(ValidTime.new('1234').to_seconds).to eq(1234)
        expect(ValidTime.new('1234m').to_seconds).to eq(1234 * 60)
        expect(ValidTime.new('1234h').to_seconds).to eq(1234 * 60 * 60)
        expect(ValidTime.new('1234d').to_seconds).to eq(1234 * 60 * 60 * 24)
      end
    end
  end

end
