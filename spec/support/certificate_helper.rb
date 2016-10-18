module CertificateHelper

  # Get a RSA private key.
  # Always same key to speed up tests.
  def ca_root_key
    @ca_root_key ||= OpenSSL::PKey::RSA.new(LetsCert::TEST::KEY_LENGTH)
  end

  # Generate a certificate for example.org, signed by #ca_root_key
  # @return [cert, domains]
  def generate_signed_cert
    unless @generated_signed_cert
      domains = %w(example.org www.example.org)

      key = OpenSSL::PKey::RSA.new(LetsCert::TEST::KEY_LENGTH)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2
      cert.issuer = OpenSSL::X509::Name.parse "/DC=letscert/CN=CA"
      cert.public_key = key.public_key
      cert.not_before = Time.now
      # 20 days validity
      cert.not_after = cert.not_before + 20 * 24 * 60 * 60
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      domains.each do |domain|
        cert.add_extension(ef.create_extension('subjectAltName',
                                               "DNS:#{domain}",
                                               false))
      end
      cert.sign(ca_root_key, OpenSSL::Digest::SHA256.new)

      @generated_signed_cert = [cert, domains]
    end

    @generated_signed_cert
  end
end
