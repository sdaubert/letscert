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
      end

      it '--valid-min option accepts minute format' do
        minutes = 156
        ARGV << '--valid-min' << "#{minutes}m"

        runner.parse_options
        expect(runner.options[:valid_min].to_seconds).to eq(minutes * 60)
      end

      it '--valid-min option accepts hour format' do
        hours = 4
        ARGV << '--valid-min' << "#{hours}h"

        runner.parse_options
        expect(runner.options[:valid_min].to_seconds).to eq(hours * 3600)
      end

      it '--valid-min option accepts day format' do
        days = 20
        ARGV << '--valid-min' << "#{days}d"

        runner.parse_options
        expect(runner.options[:valid_min].to_seconds).to eq(days * 24 * 3600)
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
            ARGV << '-f' << needed[i]
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

  end

end
