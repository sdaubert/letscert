require_relative 'spec_helper'

module LetsCert

  describe Runner do

    context '#parse_options' do

      it 'accepts --domain with DOMAIN only'
      it 'accepts --domain with DOMAIN:PATH'
      it 'accepts multiple domains with --domain option'
      it 'sets default root path with --default-root for domains without PATH'
      it 'accepts multiples files with --file option'
      it '--file option only accepts some predefined values'
      it 'sets minimum validity time with --valid-min option'
      it '--valid-min option accepts minute format'
      it '--valid-min option accepts hour format'
      it '--valid-min option accepts day format'
    end

  end

end
