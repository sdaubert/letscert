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
require 'acme-client'
require_relative 'loggable'

# rubocop:disable Metrics/ClassLength, Style/MultilineBlockLayout
# rubocop:disable Style/BlockEndNewline, Style/BlockDelimiters
module LetsCert

  # Class to handle ACME operations on certificates
  # @author Sylvain Daubert
  class Certificate
    include Loggable

    # @return [OpenSSL::X509::Certificate,nil]
    attr_reader :cert
    # Certification chain. Only set by {#get}.
    # @return [Array<OpenSSL::X509::Certificate>]
    attr_reader :chain
    # @return [Acme::Client,nil]
    attr_reader :client

    # @param [OpenSSL::X509::Certificate,nil] cert
    def initialize(cert)
      @cert = cert
      @chain = []
    end

    # Get a new certificate, or renew an existing one
    # @param [OpenSSL::PKey::PKey,nil] account_key private key to
    #   authenticate to ACME server
    # @param [OpenSSL::PKey::PKey, nil] key private key from which make a
    #   certificate. If +nil+, generate a new one with +options[:cet_key_size]+
    #   bits.
    # @param [Hash] options option hash
    # @option options [Fixnum] :account_key_size ACME account private key size
    #   in bits
    # @option options [Fixnum] :cert_key_size private key size used to generate
    #    a certificate
    # @option options [String] :email e-mail used as ACME account
    # @option options [Array<String>] :files plugin names to use
    # @option options [Boolean] :reuse_key reuse private key when getting a new
    #    certificate
    # @option options [Hash] :roots hash associating domains as keys to web
    #   roots as values
    # @option options [String] :server ACME servel URL
    # @return [void]
    # @raise [Acme::Client::Error] error in protocol ACME with server
    # @raise [Error] issue with domain name, challenge fails,...
    def get(account_key, key, options)
      logger.info { 'create key/cert/chain...' }
      check_roots(options[:roots])
      logger.debug { "webroots are: #{options[:roots].inspect}" }

      client = get_acme_client(account_key, options)

      do_challenges client, options[:roots]

      pkey = if options[:reuse_key]
               raise Error, 'cannot reuse a non-existing key' if key.nil?
               logger.info { 'Reuse existing private key' }
               generate_certificate_from_pkey options[:roots].keys, key
             else
               logger.info { 'Generate new private key' }
               generate_certificate options[:roots].keys,
                                    options[:cert_key_size]
             end

      options[:files] ||= []
      options[:files].each do |plugname|
        IOPlugin.registered[plugname].save(account_key: client.private_key,
                                           key: pkey, cert: @cert,
                                           chain: @chain)
      end
    end

    # Revoke certificate
    # @param [OpenSSL::PKey::PKey] account_key
    # @param [Hash] options
    # @option options [Fixnum] :account_key_size ACME account private key size
    #   in bits
    # @option options [String] :email e-mail used as ACME account
    # @option options [String] :server ACME servel URL
    # @return [Boolean]
    # @raise [Error] no certificate to revole.
    def revoke(account_key, options = {})
      raise Error, 'no certification data to revoke' if @cert.nil?

      client = get_acme_client(account_key, options)
      result = client.revoke_certificate(@cert)

      if result
        logger.info { 'certificate is revoked' }
      else
        logger.warn { 'certificate is not revoked!' }
      end

      result
    end

    # Check if certificate is still valid for at least +valid_min+ seconds.
    # Also checks that +domains+ are certified by certificate.
    # @param [Array<String>] domains list of certificate domains
    # @param [Integer] valid_min minimum number of seconds of validity under
    #   which a renewal is necessary.
    # @return [Boolean]
    def valid?(domains, valid_min = 0)
      if @cert.nil?
        logger.debug { 'no existing certificate' }
        return false
      end

      subjects = []
      @cert.extensions.each do |ext|
        if ext.oid == 'subjectAltName'
          subjects += ext.value.split(/,\s*/).map { |s| s.sub(/DNS:/, '') }
        end
      end
      logger.debug { "cert SANs: #{subjects.join(', ')}" }

      # Check all domains are subjects of certificate
      unless domains.all? { |domain| subjects.include? domain }
        msg = 'At least one domain is not declared as a certificate subject. ' \
              'Backup and remove existing cert if you want to proceed.'
        raise Error, msg
      end

      !renewal_necessary?(valid_min)
    end

    # Get ACME client.
    #
    # Client is only created on first call, then it is cached.
    # @param [Hash] account_key
    # @param [Hash] options
    # @return [Acme::Client]
    def get_acme_client(account_key, options)
      return @client if @client

      key = get_account_key(account_key, options[:account_key_size])

      logger.debug { "connect to #{options[:server]}" }
      @client = Acme::Client.new(private_key: key, endpoint: options[:server])

      yield @client if block_given?

      if options[:email].nil?
        logger.warn { '--email was not provided. ACME CA will have no way to ' \
                      'contact you!' }
      end

      begin
        logger.debug { "register with #{options[:email]}" }
        registration = @client.register(contact: "mailto:#{options[:email]}")
      rescue Acme::Client::Error::Malformed => ex
        raise if ex.message != 'Registration key is already in use'
      else
        # Requesting ToS make acme-client throw an exception: Connection reset
        # by peer (Faraday::ConnectionFailed). To investigate...
        #if registration.term_of_service_uri
        #  @logger.debug { "get terms of service" }
        #  terms = registration.get_terms
        #  if !terms.nil?
        #    tos_digest = OpenSSL::Digest::SHA256.digest(terms)
        #    if tos_digest != @options[:tos_sha256]
        #      raise Error, 'Terms Of Service mismatch'
        #    end
             @logger.debug { 'agree terms of service' }
             registration.agree_terms
        #  end
        #end
      end

      @client
    end

    private

    # check webroots.
    # @param [Hash] roots
    # @raise [Error] if some domains have no defined root.
    def check_roots(roots)
      no_roots = roots.select { |_k, v| v.nil? }

      unless no_roots.empty?
        raise Error, 'root for the following domain(s) are not specified: ' \
                     "#{no_roots.keys.join(', ')}.\nTry --default_root or " \
                     'use -d example.com:/var/www/html syntax.'
      end
    end

    # Generate a new account key if no one is given in +data+
    # @param [OpenSSL::PKey,nil] key
    # @param [Integer] key_size
    # @return [OpenSSL::PKey::PKey]
    def get_account_key(key, key_size)
      if key.nil?
        logger.info { 'No account key. Generate a new one...' }
        OpenSSL::PKey::RSA.new(key_size)
      else
        key
      end
    end

    # Do ACME challenges for each requested domain.
    # @param [Acme::Client] client
    # @param [Hash] roots
    def do_challenges(client, roots)
      logger.debug { 'Get authorization for all domains' }
      challenges = get_challenges(client, roots)

      challenges.each do |domain, challenge|
        begin
          path = File.join(roots[domain], File.dirname(challenge.filename))
          FileUtils.mkdir_p path
        rescue SystemCallError => ex
          raise Error, ex.message
        end

        path = File.join(roots[domain], challenge.filename)
        logger.debug { "Save validation #{challenge.file_content} to #{path}" }
        File.write path, challenge.file_content

        challenge.request_verification
        wait_for_verification challenge, domain

        File.unlink path
      end
    end

    # Get challenges
    # @param [Acme::Client] client
    # @param [Hash] roots
    # @return [Hash] key: domain, value: authorization
    # @raise [Error] if any challenges does not support HTTP-01
    def get_challenges(client, roots)
      challenges = {}
      roots.keys.each do |domain|
        authorization = client.authorize(domain: domain)
        challenges[domain] = authorization ? authorization.http01 : nil
      end

      logger.debug { 'Check all challenges are HTTP-01' }
      if challenges.values.any?(&:nil?)
        raise Error, 'CA did not offer http-01-only challenge. ' \
                     'This client is unable to solve any other challenges.'
      end

      challenges
    end

    def wait_for_verification(challenge, domain)
      status = 'pending'
      while status == 'pending'
        sleep(1)
        status = challenge.verify_status
      end

      if status != 'valid'
        logger.warn { "#{domain} was not successfully verified!" }
      else
        logger.info { "#{domain} was successfully verified." }
      end
    end

    # Check if a renewal is necessary
    # @param [Number] valid_min minimum validity in seconds to ensure
    # @return [Boolean]
    def renewal_necessary?(valid_min)
      now = Time.now.utc
      diff = (@cert.not_after - now).to_i
      logger.debug { "Certificate expires in #{diff}s on #{@cert.not_after}" \
                     " (relative to #{now})" }

      diff < valid_min
    end

    # Generate new certificate for given domains with existing private key
    # @param [Array<String>] domains
    # @param [OpenSSL::PKey::PKey] pkey private key to use
    # @return [OpenSSL::PKey::PKey] +pkey+
    def generate_certificate_from_pkey(domains, pkey)
      csr = Acme::Client::CertificateRequest.new(names: domains,
                                                 private_key: pkey)
      acme_cert = client.new_certificate(csr)
      @cert = acme_cert.x509
      @chain = acme_cert.x509_chain

      pkey
    end

    # Generate new certificate for given domains
    # @param [Array<String>] domains
    # @param [Integer] pkey_size size in bits for private key to generate
    # @return [OpenSSL::PKey::PKey] generated private key
    def generate_certificate(domains, pkey_size)
      pkey = OpenSSL::PKey::RSA.generate(pkey_size)
      generate_certificate_from_pkey domains, pkey
    end

  end
end
