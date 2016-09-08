module LetsCert

  # Mixin for IOPmugin subclasses that handle files
  # @author Sylvain Daubert
  module FileIOPluginMixin

    # Load data from file named +#name+
    # @return [Hash]
    def load
      logger.debug { "Loading #{@name}" }

      begin
        content = File.read(@name)
      rescue Errno::ENOENT => ex
        logger.info { "no #{@name} file" }
        return self.class.empty_data
      end

      load_from_content(content)
    end

    # @abstract
    # @param [String] _content
    # @return [Hash]
    def load_from_content(_content)
      raise NotImplementedError
    end

    # Save data to file +#name+
    # @param [Hash] data
    # @return [void]
    def save_to_file(data)
      return if data.nil?

      logger.info { "saving #{@name}" }
      begin
        File.open(name, 'w') do |f|
          f.write(data)
        end
      rescue Errno => ex
        @logger.error { ex.message }
        raise Error, "Error when saving #{@name}"
      end
    end

  end

end
