require 'optparse'
require 'logger'
require 'awesome_print'

require_relative 'io_plugin'

module LetsCert

  class Runner

    # Custom logger formatter
    class LoggerFormatter < Logger::Formatter

      # @private
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

      def format_datetime(time)
        time.strftime("%Y-%d-%d %H:%M:%S")
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
        cert_key_size: 4096,
        validmin: 2_592_000,
        account_key_public_exponent: 65537,
        account_key_size: 4096,
        tos_sha256: '33d233c8ab558ba6c8ebc370a509acdded8b80e5d587aa5d192193f35226540f',
        user_agent: 'letscert/0',
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

      begin
        if @options[:revoke]
          revoke
          RETURN_OK
        elsif @options[:domains].empty?
          raise Error, 'At leat one domain must be given with --domain option'
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

          if valid_existing_cert(data[:cert])
            RETURN_OK
          else
            # update/create cert
            new_data(data)
            RETURN_OK_CERT
          end
        end

      rescue Error => ex
        puts "Error: #{ex.message}"
        RETURN_ERROR
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
        opts.on('-v', '--verbose', 'Run verbosely') { |v| @options[:verbose] += 1 if v }


        opts.separator("\nWebroot manager:")

        opts.on('-d', '--domain DOMAIN[:PATH]',
                'Domain name to include in the certificate.',
                'Must be specified at least once.',
                'Its path on the disk must also be provided.') do |domain|
          @options[:domains] << domain
        end

        opts.on('--default_root PATH', 'Default webroot path',
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

    def revoke
      @logger.info { "load certificates: #{@options[:files].join(', ')}" }
      if @options[:files].empty?
        raise Error, 'no certificate to revoke. Pass at least one with '+
                     ' -f option.'
      end

      # Temp
      @logger.warn "Not yet implemented"
    end


    private

    def get_account_key(data)
      if data.nil?
        logger.info { 'No account key. Generate a new one...' }
        # As account key is a long term key, size is forced to 4096 bits
        OpenSSL::PKey::RSA.new(4096)
      else
        data
      end
    end

    # Get ACME client.
    #
    # Client is only created on first call, then it is cached.
    def get_acme_client(account_key)
      return @client if @client

      key = get_account_key(account_key)

      @logger.debug { "connect to #{@options[:server]}" }
      @client = Acme::Client.new(private_key: key, endpoint: @options[:server])

      if @options[:email].nil?
        @logger.warn { '--email was not provided. ACME CA will have no way to ' +
                       'contact you!' }
      end

      @logger.debug { "register with #{@options[:email]}" }
      registration = @client.register(contact: "mailto:#{@options[:email]}")
      ap registration.id
      ap registration.contact
      ap registration.uri
      ap registration.next_uri
      ap registration.recover_uri
      ap registration.term_of_service_uri

      #if registration.term_of_service_uri
      #  @logger.debug { "get terms of service" }
      #  terms = registration.get_terms
      #  if !terms.nil?
      #    tos_digest = OpenSSL::Digest::SHA256.digest(terms)
      #    if tos_digest != @options[:tos_sha256]
      #      raise Error, 'Terms Of Service mismatch'
      #    end

           @logger.debug { "agree terms of service" }
           registration.agree_terms
      #  end
      #end

      @client
    end

    # Load existing data from disk
    def load_data_from_disk(files)
      all_data = IOPlugin.empty_data

      files.each do |plugin_name|
        persisted = IOPlugin.registered[plugin_name].persisted
        data = IOPlugin.registered[plugin_name].load

        test = IOPlugin.empty_data.keys.all? do |key|
          persisted[key] or data[key].nil?
        end
        raise Error unless test

        # Merge data into all_data. New value replace old one only id old one was
        # not defined
        all_data.merge!(data) do |key, oldval, newval|
          oldval || newval
        end
      end

      all_data
    end

    # Check if +cert+ exists and is always valid
    # @todo For now, only check exitence.
    def valid_existing_cert(cert)
      if cert.nil?
        @logger.debug { 'no existing cert' }
        return false
      end

      subjects = []
      subjects << cert.subject

      cert.extensions.each do |ext|
        p ext.oid
      end
    end

    # Create/renew key/cert/chain
    def new_data(data)
      @logger.info {"create key/cert/chain..." }
      roots = compute_roots
      @logger.debug { "webroots are: #{roots.inspect}" }

      client = get_acme_client(data[:account_key])

      @logger.debug { 'Get authorization for all domains' }
      challenges = {}
      roots.keys.each do |domain|
        authorization = client.authorize(domain: domain)
         if authorization
           challenges[domain] = authorization.http01
         else
           challenges[domain] = nil
         end
      end

      @logger.debug { 'Check all challenges are HTTP-01' }
      if challenges.values.any? { |chall| chall.nil? }
        raise Error, 'CA did not offer http-01-only challenge. ' +
                     'This client is unable to solve any other challenges.'
      end


      ########### TODO ###########

      # To uncomment when TODO will be done
      #IOPlugin.registered.each do |name, plugin|
      #  plugin.save({ account_key: client.private_key })
      #end
    end

    # Compute webroots
    # @return [Hash] whre key are domains and value are their webroot path
    def compute_roots
      roots = {}
      no_roots = []

      @options[:domains].each do |domain|
        match = domain.match(/([\w+\.]+):(.*)/)
        if match
          roots[match[1]] = match[2]
        elsif @options[:default_path]
          roots[domain] = @options[:default_path]
        else
          no_roots << domain
        end
      end

      if !no_roots.empty?
        raise Error, 'root for the following domain(s) are not specified: ' +
                     no_roots.join(', ') + ".\nTry --default_root or use " +
                     '-d example.com:/var/www/html syntax.'
      end

      roots
    end

  end

end
