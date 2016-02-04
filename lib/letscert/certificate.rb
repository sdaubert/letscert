module LetsCert

  # Class to handle ACME operations on certificates
  class Certificate

    # Set logger
    # @param [Logger] logger
    def self.logger=(logger)
      @@logger = logger
    end

    # Get logger instance
    # @return [Logger]
    def logger
      @logger ||= self.class.class_variable_get(:@@logger)
    end

    # Revoke certificates
    # @param [Array<String>] files
    def self.revoke(files)
      @logger.warn "revoke not yet implemented"
    end

    # Get a new certificate, or renew an existing one
    # @param [Hash] data
    def self.get(data)
    end
  end

end
