require 'openssl'

module LetsCert
  # Ruby < 2.4 has bugs in OpenSSL. This class patches these bugs.
  # @author Sylvain Daubert
  class PatchedECPkey < OpenSSL::PKey::EC
    alias :private? :private_key?
    alias :public? :public_key?

    # Say if {PatchedECPkey} is needed
    # @return [Boolean]
    def self.needed?
      RbConfig::CONFIG['MAJOR'] == '2' && RbConfig::CONFIG['MINOR'].to_i < 4
    end
  end
end
