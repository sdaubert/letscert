require_relative 'spec_helper'

module LetsCert

  describe Certificate do

    before(:all) { Certificate.logger = Logger.new('/dev/null') }

    before(:all) do
      root_key = OpenSSL::PKey::RSA.new(512)

      @domains = %w(example.org www.example.org)

      key = OpenSSL::PKey::RSA.new(512)
      @cert = OpenSSL::X509::Certificate.new
      @cert.version = 2
      @cert.serial = 2
      @cert.issuer = OpenSSL::X509::Name.parse "/DC=letscert/CN=CA"
      @cert.public_key = key.public_key
      @cert.not_before = Time.now
      # 20 days validity
      @cert.not_after = @cert.not_before + 20 * 24 * 60 * 60
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = @cert
      @domains.each do |domain|
        @cert.add_extension(ef.create_extension('subjectAltName',
                                                "DNS:#{domain}",
                                                false))
      end
        @cert.sign(root_key, OpenSSL::Digest::SHA256.new)
    end

    let(:certificate) { Certificate.new(@cert) }

    context '#get' do

      it 'checks all domains have a root' do
        runner = Runner.new
        ARGV.clear

        ARGV << '-d' << 'example.com:/var/ww/html'
        runner.parse_options
        # raise error because no e-mail address was given
        expect { certificate.get(nil, nil, runner.options) }.
          to raise_error(Acme::Client::Error)

        ARGV.clear
        ARGV << '-d' << 'example.com:/var/www/html'
        ARGV << '-d' << 'www.example.com'
        runner.options[:domains] = []
        runner.parse_options
        expect { certificate.get(nil, nil, runner.options) }.
          to raise_error(LetsCert::Error).
              with_message(/not specified: www\.example\.com\./)

        ARGV.clear
        ARGV << '-d' << 'example.com:/var/www/html'
        ARGV << '-d' << 'www.example.com'
        ARGV << '--default-root' << '/opt/www'
        p ARGV
        runner.parse_options
        # raise error because no e-mail address was given
        expect { certificate.get(nil, nil, runner.options) }.
          to raise_error(Acme::Client::Error)
        expect(runner.options[:roots]['example.com']).to eq('/var/www/html')
        expect(runner.options[:roots]['www.example.com']).to eq('/opt/www')
      end

      it 'uses existing account key'
      it 'creates an ACME account key if non exists'
      it 'creates an ACME client with provided account key and end point'
      it 'raises when register without e-mail'

    end

    context '#valid?' do

      it 'checks whether a certificate is valid given a minimum valid duration' do
        expect(certificate.valid?(@domains)).to be(true)
        expect(certificate.valid?(@domains, 19)).to be(true)
        expect(certificate.valid?(@domains, 21 * 24 * 3600)).to be(false)
      end

      it 'raises whether a certificate does not validate a given domain' do
        expect(certificate.valid?(@domains)).to be(true)
        expect(certificate.valid?(@domains[0, 1])).to be(true)

        domains = @domains + %w(another.tld)
        expect { certificate.valid?(domains) }.to raise_error(LetsCert::Error)
        expect { certificate.valid?(%w(another.tld)) }.to raise_error(LetsCert::Error)
      end

    end

  end

end
