require 'tmpdir'
require 'webrick'
require_relative 'spec_helper'

module LetsCert

  TEST_SERVER = 'http://172.17.0.1:4000'


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

      # minimum size accepted by ACME server
      @account_key2048 = OpenSSL::PKey::RSA.new(2048)

      # Create temporary directory
      @tmpdir = Dir.mktmpdir('test_letscert')
    end

    after(:all) do
      # Remove temporary directory
      system "rm -rf #@tmpdir"
    end

    let(:certificate) { Certificate.new(@cert) }

    context '#get' do

      it 'checks all domains have a root' do
        runner = Runner.new
        ARGV.clear

        ARGV << '-d' << 'example.com:/var/ww/html'
        ARGV << '--server' << TEST_SERVER
        runner.parse_options
        VCR.use_cassette('single-domain') do
          # raise error because no e-mail address was given
          expect { certificate.get(nil, nil, runner.options) }.
            to raise_error(Acme::Client::Error)
        end

        ARGV.clear
        ARGV << '-d' << 'example.com:/var/www/html'
        ARGV << '-d' << 'www.example.com'
        ARGV << '--server' << TEST_SERVER
        runner.options[:domains] = []
        runner.parse_options
        expect { certificate.get(nil, nil, runner.options) }.
          to raise_error(LetsCert::Error).
              with_message(/not specified: www\.example\.com\./)

        ARGV.clear
        ARGV << '-d' << 'example.com:/var/www/html'
        ARGV << '-d' << 'www.example.com'
        ARGV << '--default-root' << '/opt/www'
        ARGV << '--server' << TEST_SERVER
        runner.parse_options
        VCR.use_cassette('default-root') do
          # raise error because no e-mail address was given
          expect { certificate.get(nil, nil, runner.options) }.
            to raise_error(Acme::Client::Error)
        end
        expect(runner.options[:roots]['example.com']).to eq('/var/www/html')
        expect(runner.options[:roots]['www.example.com']).to eq('/opt/www')
      end

      it 'uses existing account key' do
        options = { roots: { 'example.com' => '/var/www/html' } }

        VCR.use_cassette('no-server') do
          # Connection error: no server to connect to
          expect { certificate.get(@account_key2048, nil, options) }.
            to raise_error(Faraday::ConnectionFailed)
        end
        expect(certificate.client.private_key).to eq(@account_key2048)
      end

      it 'creates an ACME account key if non exists' do
        options = {
          roots: { 'example.com' => '/var/www/html' },
          account_key_size: 128,
        }

        VCR.use_cassette('no-server') do
          # Connection error: no server to connect to
          expect { certificate.get(nil, nil, options) }.
            to raise_error(Faraday::ConnectionFailed)
        end
        expect(certificate.client.private_key).to be_a(OpenSSL::PKey::RSA)
      end

      it 'creates an ACME client with provided account key and end point' do
        options = {
          roots: { 'example.com' => '/var/www/html' },
          server: TEST_SERVER,
        }

        VCR.use_cassette('create-acme-client') do
          # Acme error: not valid e-mail address
          expect { certificate.get(@account_key2048, nil, options) }.
            to raise_error(Acme::Client::Error)
        end
        expect(certificate.client.private_key).to eq(@account_key2048)
        expect(certificate.client.instance_eval { @endpoint }).to eq(options[:server])
      end

      it 'raises when register without e-mail' do
        options = {
          roots: { 'example.com' => '/var/www/html' },
          server: TEST_SERVER,
        }

        VCR.use_cassette('create-acme-client-but-bad-email') do
          # Acme error: not valid e-mail address
          expect { certificate.get(@account_key2048, nil, options) }.
            to raise_error(Acme::Client::Error).
                with_message('not a valid e-mail address')
        end
      end

      it 'responds to HTTP-01 challenge' do
        options = {
          roots: { 'example.com' => @tmpdir },
          server: TEST_SERVER,
          email: 'test@example.org',
          cert_key_size: 2048,
        }

        VCR.use_cassette('http-01-challenge') do
          serve_files_from @tmpdir do
            certificate.get_acme_client(@account_key2048, options)
            expect { certificate.get(@account_key2048, nil, options) }.
              to_not raise_error
          end
        end
        expect(certificate.cert).to_not eq(@cert)
      end

      it 'raises if HTTP-01 challenge is unavailable' do
        options = {
          roots: { 'example.com' => '/var/www/html' },
          server: TEST_SERVER,
          email: 'test@example.org',
        }

        VCR.use_cassette('no-http-01-challenge') do
          certificate.get_acme_client(@account_key2048, options) do |client|
            client.connection.builder.insert 0, RemoveHttp01Middleware
          end
          expect { certificate.get(@account_key2048, nil, options) }.
            to raise_error(LetsCert::Error).with_message(/not offer http-01/)
        end
      end

      it 'reuses existing private key if --reuse-key is present'

    end

    context '#revoke' do
      it 'raises if no certificate is given' do
        certificate = Certificate.new(nil)
        expect { certificate.revoke(@account_key2048) }.
          to raise_error(LetsCert::Error)
      end

      it 'revokes an existing certificate'
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
