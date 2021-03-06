module LetsCert
  module TEST

    # RSA key length for test.
    # Use minimal key length to speed up tests.
    KEY_LENGTH = 2048

    # URI to ACME test server
    SERVER = 'http://172.17.0.1:4000'

    # Files used by runner specs
    RUNNER_FILES = %w(account_key.json key.der cert.pem chain.pem)
  end
end
