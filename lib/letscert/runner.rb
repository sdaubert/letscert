# The MIT License (MIT)
#
# Copyright (c) 2016 Sylvain Daubert
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
require 'optparse'
require 'logger'
require 'fileutils'

require_relative 'io_plugin'
require_relative 'certificate'

module LetsCert

  # Runner class: analyse and execute CLI commands.
  # @author Sylvain Daubert
  class Runner
    # Get options
    # @return [Hash]
    attr_reader :options

    # Custom logger formatter
    class LoggerFormatter < Logger::Formatter

      # @private log format
      FORMAT = "[%s] %5s: %s\n"

      # @param [String] severity
      # @param [Datetime] time
      # @param [nil,String] progname
      # @param [String] msg
      # @return [String]
      def call(severity, time, progname, msg)
        FORMAT % [format_datetime(time), severity, msg2str(msg)]
      end


      private

      # @private simple datetime formatter
      # @param [DateTime] time
      # @return [String]
      def format_datetime(time)
        time.strftime("%Y-%m-%d %H:%M:%S")
      end

    end


    # Exit value for OK
    RETURN_OK = 1
    # Exit value for OK but with creation/renewal of certificate data
    RETURN_OK_CERT = 0
    # Exit value for error(s)
    RETURN_ERROR = 2
    
    # @return [Logger]
    attr_reader :logger

    # Run LetsCert
    # @return [Integer]
    # @see #run
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
        cert_key_size: 2048,
        valid_min: 30 * 24 * 60 * 60,
        account_key_public_exponent: 65537,
        account_key_size: 4096,
        tos_sha256: '33d233c8ab558ba6c8ebc370a509acdded8b80e5d587aa5d192193f35226540f',
        user_agent: "letscert/#{VERSION.gsub(/\..*/, '')}",
        server: 'https://acme-v01.api.letsencrypt.org/directory',
      }

      @logger = Logger.new(STDOUT)
      @logger.formatter = LoggerFormatter.new
    end

    # @return [Integer] exit code
    #   * 0 if certificate data were created or updated
    #   * 1 if renewal was not necessery
    #   * 2 in case of errors
    def run
      if @options[:print_help]
        puts @opt_parser
        exit RETURN_OK
      end

      if @options[:show_version]
        puts "letscert #{LetsCert::VERSION}"
        puts "Copyright (c) 2016 Sylvain Daubert"
        puts "License MIT: see http://opensource.org/licenses/MIT"
        exit RETURN_OK
      end

      case @options[:verbose]
      when 0
        @logger.level = Logger::Severity::WARN
      when 1
        @logger.level = Logger::Severity::INFO
      when 2..5
        @logger.level = Logger::Severity::DEBUG
      end

      @logger.debug { "options are: #{@options.inspect}" }

      IOPlugin.logger = @logger
      Certificate.logger = @logger

      begin
        if @options[:domains].empty?
          raise Error, "At leat one domain must be given with --domain option.\n" +
                       "Try 'letscert --help' for more information."
        end

        if @options[:revoke]
          data = load_data_from_disk(IOPlugin.registered.keys)
          certificate = Certificate.new(data[:cert])
          if certificate.revoke(data[:account_key], @options)
            RETURN_OK
          else
            RETURN_ERROR
          end
        else
          # Check all components are covered by plugins
          persisted = IOPlugin.empty_data
          @options[:files].each do |file|
            persisted.merge!(IOPlugin.registered[file].persisted) do |k, oldv, newv|
              oldv || newv
            end
          end
          not_persisted = persisted.keys.find_all { |k| !persisted[k] }
          unless not_persisted.empty?
            raise Error, 'Selected IO plugins do not cover following components: ' +
                         not_persisted.join(', ')
          end

          data = load_data_from_disk(@options[:files])

          certificate = Certificate.new(data[:cert])
          if certificate.valid?(@options[:domains], @options[:valid_min])
            @logger.info { 'no need to update cert' }
            RETURN_OK
          else
            # update/create cert
            certificate.get data[:account_key], data[:key], @options
            RETURN_OK_CERT
          end
        end

      rescue Error, Acme::Client::Error => ex
        @logger.error ex.message
        puts "Error: #{ex.message}"
        RETURN_ERROR
      end
    end


    # Parse line command options
    # @raise [OptionParser::InvalidOption] on unrecognized or malformed option
    # @return [void]
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
        opts.on('-v', '--verbose', 'Run verbosely') { |v| @options[:verbose] += 1 if v }


        opts.separator("\nWebroot manager:")

        opts.on('-d', '--domain DOMAIN[:PATH]',
                'Domain name to include in the certificate.',
                'Must be specified at least once.',
                'Its path on the disk must also be provided.') do |domain|
          @options[:domains] << domain
        end

        opts.on('--default-root PATH', 'Default webroot path',
                'Use for domains without PATH part.') do |path|
          @options[:default_root] = path
        end

        opts.separator("\nCertificate data files:")

        opts.on('--revoke', 'Revoke existing certificates') do |revoke|
          @options[:revoke] = revoke
        end

        opts.on("-f", "--file FILE", 'Input/output file.',
                'Can be specified multiple times',
                'Allowed values: account_key.json, cert.der,',
                'cert.pem, chain.pem, full.pem,',
                'fullchain.pem, key.der, key.pem.') do |file|
          @options[:files] << file
        end

        opts.on('--cert-key-size BITS', Integer,
                'Certificate key size in bits',
                "(default: #{@options[:cert_key_size]})") do |bits|
          @options[:cert_key_size] = bits
        end

        opts.on('--valid-min SECONDS', Integer, 'Renew existing certificate if validity',
                'is lesser than SECONDS', '(default: 2592000 (30 days))') do |time|
          @options[:valid_min] = time
        end

        opts.on('--reuse-key', 'Reuse previous private key') do |rk|
          @options[:reuse_key] = rk
        end

        opts.separator("\nRegistration:")
        opts.separator("  Automatically register an account with he ACME CA specified" +
                       " by --server")
        opts.separator('')

        opts.on('--account-key-size BITS', Integer,
                "Account key size (default: #{@options[:account_key_size]})") do |bits|
          @options[:account_key_size] = bits
        end

        opts.on('--tos-sha256 HASH', String,
                'SHA-256 digest of the content of Terms',
                'Of Service URI') do |hash|
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
                "(default: #{@options[:user_agent]})") do |ua|
          @options[:user_agent] = ua
        end
        
        opts.on('--server URI', 'URI for the CA ACME API endpoint',
                "(default: #{@options[:server]})") do |uri|
          @options[:server] = uri
        end
      end

      @opt_parser.parse!
      compute_roots
    end


    private

    # Load existing data from disk
    # @param [Array<String>] files
    # @return [Hash]
    def load_data_from_disk(files)
      all_data = IOPlugin.empty_data

      files.each do |plugin_name|
        persisted = IOPlugin.registered[plugin_name].persisted
        data = IOPlugin.registered[plugin_name].load

        test = IOPlugin.empty_data.keys.all? do |key|
          persisted[key] or data[key].nil?
        end
        raise Error unless test

        # Merge data into all_data. New value replace old one only if old one was
        # not defined
        all_data.merge!(data) do |key, oldval, newval|
          oldval || newval
        end
      end

      all_data
    end

    # Compute webroots and set +@options[:roots]+
    # @return [Hash] where keys are domains and value are their webroot path
    def compute_roots
      roots = {}

      @options[:domains].each do |domain|
        match = domain.match(/([-\w\.]+):(.*)/)
        if match
          roots[match[1]] = match[2]
        elsif @options[:default_root]
          roots[domain] = @options[:default_root]
        else
          roots[domain] = nil
        end
      end

      @options[:roots] = roots
    end

  end

end
