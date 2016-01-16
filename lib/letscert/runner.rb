require 'optparse'
require 'logger'

module LetsCert

  class Runner
    # @return [Logger]
    attr_reader :logger

    def self.run
      runner = new
      runner.parse_options
      runner.run
    end


    def initialize
      @options = {
        verbose: 0,
        domains: [],
        files: [],
        cert_key_size: 4096,
        validmin: 2_592_000,
        account_key_public_exponent: 65537,
        account_key_size: 4096,
        tos_sha256: '33d233c8ab558ba6c8ebc370a509acdded8b80e5d587aa5d192193f35226540f',
        user_agent: 'letscert/0',
        server: 'https://acme-v01.api.letsencrypt.org/directory',
      }

      @logger = Logger.new(STDOUT)
    end

    def run
      if @options[:print_help]
        puts @opt_parser
        exit
      end

      if @options[:show_version]
        puts "letscert #{LetsCert::VERSION}"
        puts "Copyright (c) 2016 Sylvain Daubert"
        puts "License MIT: see http://opensource.org/licenses/MIT"
        exit
      end

      case @options[:verbose]
      when 0
        @logger.level = Logger::Severity::WARN
      when 1
        @logger.level = Logger::Severity::INFO
      when 2..5
        @logger.level = Logger::Severity::DEBUG
      end
    end


    def parse_options
      @opt_parser = OptionParser.new do |opts|
        opts.banner = "Usage: lestcert [options]"

        opts.separator('')

        opts.on('-h', '--help', 'Show this help message and exit') do
          @options[:print_help] = true
        end
        opts.on('-V', '--version', 'Show version and exit') do |v|
          @options[:show_version] = v
        end
        opts.on('-v', '--verbose', 'Run verbosely') { |v| @options[:verbose] = v }
        

        opts.separator("\nWebroot manager:")

        opts.on('-d', '--domain DOMAIN[:PATH]',
                'Domain name to include in the certificate.',
                'Must be specified at least once.',
                'Its path on the disk must also be provided.') do |domain|
          @options[:domains] << domain
        end

        opts.on('--default_root PATH', 'Default webroot path',
                'Use for all domains (nor need for PATH part',
                'of --domain DOMAIN:PATH)') do |path|
          @options[:default_root] = path
        end

        opts.separator("\nCertificate data files:")

        opts.on("-f", "--file FILE", 'Input/output file.',
                'an be specified multiple times',
                'Allowed values: account_key.json, cert.der,',
                'cert.pem, chain.pem, xternal.sh, full.pem,',
                'fullchain.pem, key.der, key.pem.') do |file|
          @options[:files] << file
        end

        opts.on('--cert-key-size BITS', Integer,
                'Certificate key size in bits',
                '(default: 4096)') do |bits|
          @options[:cert_key_size] = bits
        end

        opts.on('--valid-min SECONDS', Integer, 'Minimum validity of the resulting',
                'certificate (default: 2592000 (30 days))') do |time|
          @options[:valid_min] = time
        end

        opts.separator("\nRegistration:")
        opts.separator("  Automatically register an account with he ACME CA specified" +
                       " by --server")
        opts.separator('')

        opts.on('--account-key-public-exponent BITS', Integer,
                'Account key public exponent value (default: 65537)') do |bits|
          @options[:account_key_public_exponent] = bits
        end

        opts.on('--account-key-size BITS', Integer,
                'Account key size (default: 4096)') do |bits|
          @options[:account_key_size] = bits
        end

        opts.on('--tos-sha256 HASH', String,
                'SHA-256 digest of the content of Terms Of Service URI') do |hash|
          @options[:tos_sha256] = hash
        end

        opts.on('--email EMAIL', String,
                'E-mail address. CA is likely to use it to',
                'remind about expiring certificates, as well',
                'as for account recovery. It is highly',
                'recommended to set this value.') do |email|
          @options[:email] = email
        end

        opts.separator("\nHTTP:")
        opts.separator('  Configure properties of HTTP requests and responses.')
        opts.separator('')

        opts.on('--user-agent NAME', 'User-Agent sent in all HTTP requests',
                '(default: letscert/0)') do |ua|
          @options[:user_agent] = ua
        end
        
        opts.on('--server URI', 'URI for the CA ACME API endpoint',
                '(default: https://acme-v01.api.letsencrypt.org/directory)') do |uri|
          @options[:server] = uri
        end
      end

      @opt_parser.parse!
    end

  end

end
