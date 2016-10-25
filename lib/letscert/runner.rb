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
require_relative 'runner/logger_formatter'
require_relative 'runner/valid_time'

module LetsCert

  # Runner class: analyse and execute CLI commands.
  # @author Sylvain Daubert
  # rubocop:disable Metrics/ClassLength
  class Runner

    # Exit value for OK
    RETURN_OK = 1
    # Exit value for OK but with creation/renewal of certificate data
    RETURN_OK_CERT = 0
    # Exit value for error(s)
    RETURN_ERROR = 2

    # Default key size for RSA certificates
    RSA_DEFAULT_KEY_SIZE = 2048

    # Get options
    # @return [Hash]
    attr_reader :options
    # @return [Logger]
    attr_accessor :logger

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
        valid_min: ValidTime.new('30d'),
        account_key_size: 4096,
        tos_sha256: '33d233c8ab558ba6c8ebc370a509acdded8b80e5d587aa5d192193f3' \
                    '5226540f',
        server: 'https://acme-v01.api.letsencrypt.org/directory'
      }

      @logger = Logger.new($stdout)
      @logger.formatter = LoggerFormatter.new
    end

    # @return [Integer] exit code
    #   * 0 if certificate data were created or updated
    #   * 1 if renewal was not necessery
    #   * 2 in case of errors
    def run
      print_help_if_needed
      show_version_if_needed
      set_logger_level
      set_logger

      begin
        check_domains
        if @options[:revoke]
          revoke
        else
          check_persisted
          get_certificate
        end
      rescue Error, Acme::Client::Error => ex
        msg = ex.message
        msg = "[Acme] #{msg}" if ex.is_a?(Acme::Client::Error)
        @logger.error msg
        $stderr.puts "Error: #{msg}"
        RETURN_ERROR
      end
    end

    # Parse line command options
    # @raise [OptionParser::InvalidOption] on unrecognized or malformed option
    # @return [void]
    # rubocop:disable Metrics/MethodLength
    def parse_options
      @opt_parser = OptionParser.new do |opts|
        opts.banner = 'Usage: lestcert [options]'

        opts.separator('')

        opts.on('-h', '--help', 'Show this help message and exit') do
          @options[:print_help] = true
        end
        opts.on('-V', '--version', 'Show version and exit') do |v|
          @options[:show_version] = v
        end
        opts.on('-v', '--verbose', 'Run verbosely') do |v|
          @options[:verbose] += 1 if v
        end

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

        opts.on('-f', '--file FILE', 'Input/output file.',
                'Can be specified multiple times',
                'Allowed values: account_key.json, cert.der,',
                'cert.pem, chain.pem, full.pem,',
                'fullchain.pem, key.der, key.pem.') do |file|
          @options[:files] << file
        end

        opts.on('--cert-ecdsa CURVE', Integer,
                'Generate ECDSA certificate for CURVE') do |bits|
          @options[:cert_key_size] = bits
          @options[:sig_scheme] = :ecdsa
        end

        opts.on('--cert-rsa BITS', Integer,
                'Generate RSA certificate with a BITS-bit key') do |bits|
          @options[:cert_key_size] = bits
          @options[:sig_scheme] = :rsa
        end
        opts.on('--cert-key-size BITS', Integer,
                'Certificate key size in bits',
                '(equivalent to --cert-rsa)',
                "(default: #{RSA_DEFAULT_KEY_SIZE})") do |bits|
          @options[:cert_key_size] = bits
          @options[:sig_scheme] = :rsa
        end

        opts.accept(ValidTime) do |valid_time|
          ValidTime.new(valid_time)
        end
        opts.on('--valid-min TIME', ValidTime,
                'Renew existing certificate if validity',
                'is lesser than TIME',
                "(default: #{@options[:valid_min]})") do |vt|
          @options[:valid_min] = vt
        end

        opts.on('--reuse-key', 'Reuse previous private key') do |rk|
          @options[:reuse_key] = rk
        end

        opts.separator("\nRegistration:")
        opts.separator('  Automatically register an account with he ACME CA' \
                       ' specified  by --server')
        opts.separator('')

        opts.on('--account-key-size BITS', Integer,
                'Account key size (default: ' \
                "#{@options[:account_key_size]})") do |bits|
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

        opts.on('--server URI', 'URI for the CA ACME API endpoint',
                "(default: #{@options[:server]})") do |uri|
          @options[:server] = uri
        end
      end

      @opt_parser.parse!
      compute_roots
      select_default_cert_type_if_none_specified
    end

    # Check all components are covered by plugins
    # @raise [Error]
    def check_persisted
      persisted = persisted_data
      not_persisted = persisted.keys.find_all { |k| persisted[k].nil? }

      unless not_persisted.empty?
        raise Error, 'Selected IO plugins do not cover following components: ' +
                     not_persisted.join(', ')
      end
    end

    private

    # Print help and exit, if +:print_help+ option is set
    # @return [void]
    # rubocop:disable Style/GuardClause
    def print_help_if_needed
      if @options[:print_help]
        show_version
        puts @opt_parser
        exit RETURN_OK
      end
    end

    # Show version and exit, if +:show_version+ option is set
    # @return [void]
    def show_version_if_needed
      if @options[:show_version]
        show_version
        exit RETURN_OK
      end
    end

    def show_version
      puts "letscert #{LetsCert::VERSION}"
      puts 'Copyright (c) 2016 Sylvain Daubert'
      puts 'License MIT: see http://opensource.org/licenses/MIT'
    end

    # Set logger level from +:verbose+ option
    # @return [void]
    def set_logger_level
      case @options[:verbose]
      when 0
        @logger.level = Logger::Severity::WARN
      when 1
        @logger.level = Logger::Severity::INFO
      when 2..5
        @logger.level = Logger::Severity::DEBUG
      end
    end

    # Set logger for IOPlugin and Certificate classes.
    # @return [void]
    def set_logger
      @logger.debug { "options are: #{@options.inspect}" }
      IOPlugin.logger = @logger
      Certificate.logger = @logger
    end

    # Check at least on domain is given.
    # @return [void]
    # @raise [Error] no domain given
    def check_domains
      if @options[:domains].empty?
        raise Error, 'At leat one domain must be given with --domain ' \
                     "option.\nTry 'letscert --help' for more information."
      end
    end

    # Revoke a certificate
    # @return [Integer] exit status
    def revoke
      data = load_data_from_disk(IOPlugin.registered.keys)
      certificate = Certificate.new(data[:cert])
      if certificate.revoke(data[:account_key], @options)
        RETURN_OK
      else
        RETURN_ERROR
      end
    end

    # Create/update a certificate
    # @return [Integer] exit status
    # rubocop:disable Style/AccessorMethodName
    def get_certificate
      data = load_data_from_disk(@options[:files])

      certificate = Certificate.new(data[:cert])
      min_time = @options[:valid_min].to_seconds
      if certificate.valid?(@options[:domains], min_time)
        @logger.info { 'no need to update cert' }
        RETURN_OK
      else
        # update/create cert
        certificate.get data[:account_key], data[:key], @options
        RETURN_OK_CERT
      end
    end

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

        # Merge data into all_data. New value replace old one only if old
        # one was not defined
        all_data.merge!(data) do |_key, oldval, newval|
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

    def select_default_cert_type_if_none_specified
      if @options[:cert_ecdsa].nil? and @options[:cert_rsa].nil? and
         @options[:cert_key_size].nil?
        @options[:cert_key_size] = RSA_DEFAULT_KEY_SIZE
      end
    end

    def persisted_data
      persisted = IOPlugin.empty_data
      @options[:files].each do |file|
        ioplugin = IOPlugin.registered[file]
        next if ioplugin.nil?
        persisted.merge!(ioplugin.persisted) do |_k, oldv, newv|
          oldv || newv
        end
      end
      persisted
    end

  end

end
