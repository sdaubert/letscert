require 'openssl'

class OpenSSL::PKey::EC
  alias :private? :private_key?
  alias :public? :public_key?
end
