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
require_relative 'loggable'

module LetsCert

  # Class to handle ACME operations on certificates
  # @author Sylvain Daubert
  class Certificate
    include Loggable


    # @param [OpenSSL::X509::Certificate,nil] cert
    def initialize(cert)
      @cert = cert
    end

    # Get a new certificate, or renew an existing one
    # @param [OpenSSL::PKey::PKey] account_key private key to authenticate to ACME server
    # @param [OpenSSL::PKey::PKey] key private key from which make a certificate
    # @param [Hash] data
    def get(account_key, key, options)
      logger.info {"create key/cert/chain..." }
      roots = compute_roots(options)
      logger.debug { "webroots are: #{roots.inspect}" }

      client = get_acme_client(account_key, options)

      do_challenges client, roots

      if options[:reuse_key] and !key.nil?
        logger.info { 'Reuse existing private key' }
      else
        logger.info { 'Generate new private key' }
        key = OpenSSL::PKey::RSA.generate(options[:cert_key_size])
      end

      csr = Acme::Client::CertificateRequest.new(names: roots.keys,
                                                 private_key: key)
      cert = client.new_certificate(csr)

      options[:files].each do |plugname|
        IOPlugin.registered[plugname].save(account_key: client.private_key,
                                           key: key, cert: cert.x509,
                                           chain: cert.x509_chain)
      end
    end

    # Revoke certificate
    # @param [OpenSSL::PKey::PKey] account_key
    # @return [Boolean]
    def revoke(account_key, options)
      if @cert.nil?
        raise Error, 'no certification data to revoke'
      end

      client = get_acme_client(account_key, options)
      begin
        result = client.revoke_certificate(@cert)
      rescue Exception => ex
        raise
      end

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
    # @param [Integer] valid_min
    # @return [Boolean]
    def valid?(domains, valid_min=0)
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
        raise Error, "At least one domain is not declared as a certificate subject." +
                     "Backup and remove existing cert if you want to proceed"
      end

      !renewal_necessary?(valid_min)
    end


    private

    # Compute webroots
    # @return [Hash] whre key are domains and value are their webroot path
    def compute_roots(options)
      roots = {}
      no_roots = []

      options[:domains].each do |domain|
        match = domain.match(/([\w+\.]+):(.*)/)
        if match
          roots[match[1]] = match[2]
        elsif options[:default_root]
          roots[domain] = options[:default_root]
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

    # Get ACME client.
    #
    # Client is only created on first call, then it is cached.
    # @param [Hash] account_key
    # @param [Hash] options
    def get_acme_client(account_key, options)
      return @client if @client

      key = get_account_key(account_key, options[:account_key_size])

      logger.debug { "connect to #{options[:server]}" }
      @client = Acme::Client.new(private_key: key, endpoint: options[:server])

      if options[:email].nil?
        logger.warn { '--email was not provided. ACME CA will have no way to ' +
                       'contact you!' }
      end

      begin
        logger.debug { "register with #{options[:email]}" }
        registration = @client.register(contact: "mailto:#{options[:email]}")
      rescue Acme::Client::Error::Malformed => ex
        if ex.message != 'Registration key is already in use'
          raise
        end
      else
        # Requesting ToS make acme-client throw an exception: Connection reset by peer
        # (Faraday::ConnectionFailed). To investigate...
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
      end

      @client
    end

    # Generate a new account key if no one is given in +data+
    # @param [OpenSSL::PKey,nil] key
    # @param [Hash] options
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
      challenges = {}

      roots.keys.each do |domain|
        authorization = client.authorize(domain: domain)
         if authorization
           challenges[domain] = authorization.http01
         else
           challenges[domain] = nil
         end
      end

      logger.debug { 'Check all challenges are HTTP-01' }
      if challenges.values.any? { |chall| chall.nil? }
        raise Error, 'CA did not offer http-01-only challenge. ' +
                     'This client is unable to solve any other challenges.'
      end

      challenges.each do |domain, challenge|
        begin
          FileUtils.mkdir_p(File.join(roots[domain], File.dirname(challenge.filename)))
        rescue SystemCallError => ex
          raise Error, ex.message
        end

        path = File.join(roots[domain], challenge.filename)
        logger.debug { "Save validation #{challenge.file_content} to #{path}" }
        File.write path, challenge.file_content

        challenge.request_verification

        status = 'pending'
        while(status == 'pending') do
          sleep(1)
          status = challenge.verify_status
        end

        if status != 'valid'
          logger.warn { "#{domain} was not successfully verified!" }
        else
          logger.info { "#{domain} was successfully verified." }
        end

        File.unlink path
      end
    end

    # Check if a renewal is necessary for +cert+
    # @param [OpenSSL::X509::Certificate] cert
    # @param [Number] valid_min minimum validity in seconds to ensure
    # @return [Boolean]
    def renewal_necessary?(valid_min)
      now = Time.now.utc
      diff = (@cert.not_after - now).to_i
      logger.debug { "Certificate expires in #{diff}s on #{@cert.not_after}" +
                     " (relative to #{now})" }

      diff < valid_min
    end

  end

end
