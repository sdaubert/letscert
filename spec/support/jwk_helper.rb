require 'base64'

module JwkHelper
  def jwk_encode(data)
    Base64.urlsafe_encode64(data).sub(/[\s=]*\z/, '')
  end
end
