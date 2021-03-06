require 'webrick'
require_relative 'spec_helper'

module LetsCert

  describe Runner do

    before(:each) { ARGV.clear }

    let(:runner) { Runner.new }

    context '#parse_options' do

      it 'accepts --domain with DOMAIN only' do
        add_option 'domain', 'example.com'

        runner.parse_options
        expect(runner.options[:domains]).to be_a(Array)
        expect(runner.options[:domains].size).to eq(1)
        expect(runner.options[:domains]).to include('example.com')
      end

      it 'accepts --domain with DOMAIN:PATH' do
        add_option 'domain', 'example.com:/var/www/html'

        runner.parse_options
        expect(runner.options[:domains]).to be_a(Array)
        expect(runner.options[:domains].size).to eq(1)
        expect(runner.options[:domains]).to include('example.com:/var/www/html')
      end

      it 'accepts multiple domains with --domain option' do
        add_option 'domain', 'example.com'
        add_option 'domain', 'www.example.com'
        add_option 'domain', 'www2.example.com'

        runner.parse_options
        expect(runner.options[:domains]).to be_a(Array)
        expect(runner.options[:domains].size).to eq(3)
        expect(runner.options[:domains]).to include('example.com')
        expect(runner.options[:domains]).to include('www.example.com')
        expect(runner.options[:domains]).to include('www2.example.com')
      end

      it 'sets default root path with --default-root for domains without PATH' do
        add_option 'domain', 'example.com'
        add_option 'domain', 'another-example.com:/var/www/html'
        add_option 'default-root', '/opt/www'

        runner.parse_options
        expect(runner.options[:default_root]).to eq('/opt/www')
        expect(runner.options[:roots]).to be_a(Hash)
        expect(runner.options[:roots]['example.com']).to eq(runner.options[:default_root])
        expect(runner.options[:roots]['another-example.com']).to eq('/var/www/html')
      end

      it 'accepts multiples files with --file option' do
        add_option 'file', 'key.pem'
        add_option 'f', 'cert.pem'
        
        runner.parse_options
        expect(runner.options[:files]).to be_a(Array)
        expect(runner.options[:files].size).to eq(2)
        expect(runner.options[:files]).to include('key.pem')
        expect(runner.options[:files]).to include('cert.pem')
      end

      it 'sets minimum validity time with --valid-min option' do
        add_option 'valid-min', '30000'
        runner.parse_options
        expect(runner.options[:valid_min].to_seconds).to eq(30000)

        ARGV.clear
        add_option 'valid-min', '300n'
        expect { runner.parse_options }.to raise_error(OptionParser::InvalidArgument)

        ARGV.clear
        add_option 'valid-min', 's'
        expect { runner.parse_options }.to raise_error(OptionParser::InvalidArgument)
      end

      it '--valid-min option accepts minute format' do
        minutes = 156
        add_option 'valid-min', "#{minutes}m"

        runner.parse_options
        expect(runner.options[:valid_min].to_seconds).to eq(minutes * 60)
      end

      it '--valid-min option accepts hour format' do
        hours = 4
        add_option 'valid-min', "#{hours}h"

        runner.parse_options
        expect(runner.options[:valid_min].to_seconds).to eq(hours * 3600)
      end

      it '--valid-min option accepts day format' do
        days = 20
        add_option 'valid-min', "#{days}d"

        runner.parse_options
        expect(runner.options[:valid_min].to_seconds).to eq(days * 24 * 3600)
      end

      it '--account-key-type accepts rsa' do
        add_option 'account-key-type', 'rsa'

        expect { runner.parse_options }.to_not raise_error
        expect(runner.options[:account_key_type]).to eq('rsa')
        expect(runner.options[:account_key_size]).to eq(4096)
      end

      it '--account-key-type accepts ecdsa' do
        add_option 'account-key-type', 'ecdsa'

        expect { runner.parse_options }.to_not raise_error
        expect(runner.options[:account_key_type]).to eq('ecdsa')
        expect(runner.options[:account_key_size]).to eq(384)
      end

      it '--account-key-type raises error for unsupported type' do
        add_option 'account-key-type', 'unknown'
        expect { runner.parse_options }.to raise_error(OptionParser::InvalidArgument)
      end

      it '--account-key-size sets the account key size' do
        add_option 'account-key-type', 'ecdsa'
        add_option 'account-key-size', 256

        runner.parse_options
        expect(runner.options[:account_key_type]).to eq('ecdsa')
        expect(runner.options[:account_key_size]).to eq(256)
      end

      it 'sets default options when no option is given' do
        runner.parse_options
        expect(runner.options.size).to eq(10)
        expect(runner.options.keys).to include(:verbose, :domains, :files, :valid_min,
                                               :account_key_type, :tos_sha256, :server,
                                               :roots, :cert_rsa)
        expect(runner.options[:verbose]).to eq(0)
        expect(runner.options[:domains]).to eq([])
        expect(runner.options[:files]).to eq([])
        expect(runner.options[:valid_min].to_s).to eq('30d')
        expect(runner.options[:account_key_type]).to eq('rsa')
        expect(runner.options[:account_key_size]).to eq(4096)
        expect(runner.options[:tos_sha256]).to be_a(String)
        expect(runner.options[:roots]).to eq({})
        expect(runner.options[:cert_rsa]).to eq(2048)
      end
    end

    it '#check_persisted checks all mandatory components are covered by files' do
      expect { runner.check_persisted }.to raise_error(LetsCert::Error)

      all_needed = [%w(account_key.json cert.pem chain.pem key.pem),
                    %w(account_key.json cert.der chain.pem key.der),
                    %w(account_key.json fullchain.pem key.pem),
                    %w(account_key.json fullchain.pem key.der)]
      all_needed.each do |needed|
        needed.size.times do |nb|
          ARGV.clear
          runner.options[:files] = []
          0.upto(nb) do |i|
            add_option 'f', needed[i]
          end
          runner.parse_options

          if nb == needed.size - 1
            expect { runner.check_persisted }.to_not raise_error
          else
            expect { runner.check_persisted }.to raise_error(LetsCert::Error)
          end
        end
      end
    end

    context '#run' do

      it 'stops and print help with --help' do
        add_option 'help'
        expect do
          expect { Runner.run }.to output(/^Usage/).to_stdout
        end.to exit_with_code(1)
      end

      it 'stops and show version with --version' do
        add_option 'version'
        expect do
          expect { Runner.run }.to output(/^letscert #{LetsCert::VERSION}/).to_stdout
        end.to exit_with_code(1)
      end

      it 'arises log level with occurences of --verbose option' do
        logger = instance_double('Logger')
        runner = Runner.new
        runner.logger = logger

        runner.parse_options
        expect(logger).to receive(:level=).with(Logger::Severity::WARN)
        expect(logger).to receive(:debug)
        expect(logger).to receive(:error)
        expect { runner.run }.to output.to_stderr

        add_option 'verbose'
        runner = Runner.new
        runner.logger = logger
        runner.parse_options
        expect(logger).to receive(:level=).with(Logger::Severity::INFO)
        expect(logger).to receive(:debug)
        expect(logger).to receive(:error)
        expect { runner.run }.to output.to_stderr

        add_option 'verbose'
        add_option 'verbose'
        runner = Runner.new
        runner.logger = logger
        runner.parse_options
        expect(logger).to receive(:level=).with(Logger::Severity::DEBUG)
        expect(logger).to receive(:debug)
        expect(logger).to receive(:error)
        expect { runner.run }.to output.to_stderr

        add_option 'verbose'
        add_option 'verbose'
        add_option 'verbose'
        runner = Runner.new
        runner.logger = logger
        runner.parse_options
        expect(logger).to receive(:level=).with(Logger::Severity::DEBUG)
        expect(logger).to receive(:debug)
        expect(logger).to receive(:error)
        expect { runner.run }.to output.to_stderr
        expect(runner.options[:verbose]).to eq(3)
      end

      it 'does not raise when an unknown --file is passed' do
        add_option 'domain', 'example.org'
        add_option 'file', 'account_key.json'
        add_option 'file', 'key.der'
        add_option 'file', 'cert.der'
        add_option 'file', 'unknown.file'
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output(/^Error: Selected IO plugins do not cover/).to_stderr
      end

      it 'stops with error when no --domain is given' do
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output("Error: At leat one domain must be given with --domain option.\nTry 'letscert --help' for more information.\n").to_stderr
      end

      it 'stops with error when not enough --file options is given' do
        add_option 'domain', 'example.org'
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output(/^Error: Selected IO plugins do not cover/).to_stderr

        add_option 'domain', 'example.org'
        add_option 'file', 'account_key.json'
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output(/^Error: Selected IO plugins do not cover/).to_stderr

        add_option 'domain', 'example.org'
        add_option 'file', 'account_key.json'
        add_option 'file', 'key.der'
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output(/^Error: Selected IO plugins do not cover/).to_stderr

        add_option 'domain', 'example.org'
        add_option 'file', 'account_key.json'
        add_option 'file', 'key.der'
        add_option 'file', 'cert.der'
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output(/^Error: Selected IO plugins do not cover/).to_stderr

        add_option 'domain', 'example.org'
        add_option 'file', 'account_key.json'
        add_option 'file', 'key.der'
        add_option 'file', 'cert.der'
        add_option 'file', 'chain.pem'
        # Plugins cover all components: this error is next check after
        # persisted_check
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output(/^Error: root for the following domain/).to_stderr

        add_option 'domain', 'example.org'
        add_option 'file', 'account_key.json'
        add_option 'file', 'key.der'
        add_option 'file', 'fullchain.pem'
        # Plugins cover all components: this error is next check after
        # persisted_check
        expect do
          expect { Runner.run }.to output(/^\[/).to_stdout
        end.to output(/^Error: root for the following domain/).to_stderr
      end

      it 'returns 1 when there is no error and certificate is still valid' do
        cert, = generate_signed_cert
        Dir.mktmpdir('test_letscert') do |dir|
          change_dir_to dir do
            File.write 'cert.pem', cert.to_pem

            add_option 'domain', 'example.org'
            add_option 'domain', 'www.example.org'
            add_option 'default-root', '/tmp'
            add_option 'valid-min', 3600   # Valid for at least one hour
            add_option 'email', 'webmaster@example.org'
            add_option 'file', 'account_key.json'
            add_option 'file', 'key.der'
            add_option 'file', 'cert.pem'
            add_option 'file', 'chain.pem'
            expect(Runner.run).to eq(1)
          end
        end
      end

      it 'returns 0 when there is no error and a new certificate is created' do
        add_option 'domain', 'example.com'
        TEST::RUNNER_FILES.each { |file| add_option 'file', file }
        add_option 'email', 'webmaster@example.com'
        add_option 'server', TEST::SERVER
        add_option 'cert-key-size', TEST::KEY_LENGTH

        Dir.mktmpdir('test_lestcert_runner') do |tmpdir|
          add_option 'default-root', tmpdir

          change_dir_to tmpdir do
            TEST::RUNNER_FILES.each { |file| expect(File.exist? file).to be(false) }

            ret = -1
            VCR.use_cassette('complete-run-to-generate-new-cert') do
              serve_files_from tmpdir do
                ret = Runner.run
              end
            end
            expect(ret).to eq(0)
            TEST::RUNNER_FILES.each { |file| expect(File.exist? file).to be(true) }
         end
        end
      end

      it 'returns 0 when there is no error and a new ECDSA certificate is created' do
        add_option 'domain', 'example.com'
        TEST::RUNNER_FILES.each { |file| add_option 'file', file }
        add_option 'email', 'webmaster@example.com'
        add_option 'server', TEST::SERVER
        add_option 'cert-ecdsa', 'secp384r1'

        Dir.mktmpdir('test_lestcert_runner') do |tmpdir|
          add_option 'default-root', tmpdir

          change_dir_to tmpdir do
            ret = -1
            VCR.use_cassette('complete-run-to-generate-new-ecdsa-cert') do
              serve_files_from tmpdir do
                ret = Runner.run
              end
            end
            expect(ret).to eq(0)
            TEST::RUNNER_FILES.each { |file| expect(File.exist? file).to be(true) }
         end
        end
      end

      it 'returns 0 when there is no error and a certificate is renewed' do
        Dir.mktmpdir('test_lestcert_runner') do |tmpdir|
          change_dir_to tmpdir do
            TEST::RUNNER_FILES.each do |file|
              f = File.join(__dir__, 'io_plugins', file)
              FileUtils.cp f, '.'
            end

            timestamps = TEST::RUNNER_FILES[1..-1].map { |file| File::Stat.new(file).mtime }

            add_option 'domain', 'example.com'
            TEST::RUNNER_FILES.each { |file| add_option 'file', file }
            add_option 'email', 'webmaster@example.com'
            add_option 'server', TEST::SERVER
            add_option 'cert-rsa',TEST::KEY_LENGTH
            add_option 'default-root', tmpdir
            add_option 'valid-min', 3600*24*31*3 # 3 months to force update

            ret = -1
            VCR.use_cassette('complete-run-to-renew-cert') do
              serve_files_from tmpdir do
                ret = Runner.run
              end
            end
            expect(ret).to eq(0)
            TEST::RUNNER_FILES[1..-2].each_with_index do |file, i|
              expect(File::Stat.new(file).mtime).to be > timestamps[i]
            end
          end
        end
      end

      it 'returns 2 on error' do
        return_value = 0
        expect do
          expect { return_value = Runner.run }.to output(/^\[/).to_stdout
        end.to output.to_stderr
        expect(return_value).to eq(2)
      end
    end
  end
end
