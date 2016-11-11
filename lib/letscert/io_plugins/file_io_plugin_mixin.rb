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
      rescue Errno::ENOENT
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
    # @raise [Error] IO error
    def save_to_file(data)
      return if data.nil?

      # Return if content did not change
      if File.exist? name
        old_content = File.read(name)
        return if old_content == data
      end

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
