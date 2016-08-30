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

  # Input/output plugin
  # @author Sylvain Daubert
  class IOPlugin
    include Loggable

    # Plugin name
    # @return [String]
    attr_reader :name

    # Registered plugins
    @registered = {}

    # Get empty data
    # @return [Hash] +{ account_key: nil, key: nil, cert: nil, chain: nil }+
    def self.empty_data
      { account_key: nil, key: nil, cert: nil, chain: nil }
    end

    # Register a plugin
    # @param [Class] klass
    # @param [Array] args args to pass to +klass+ constructor
    # @return [IOPlugin]
    def self.register(klass, *args)
      plugin = klass.new(*args)
      if plugin.name =~ %r{[/\\]} or ['.', '..'].include?(plugin.name)
        raise Error, 'plugin name should just be a file name, without path'
      end

      @registered[plugin.name] = plugin
      klass
    end

    # Get registered plugins
    # @return [Hash] keys are filenames and keys are instances of IOPlugin
    #  subclasses.
    def self.registered
      @registered
    end

    # @param [String] name
    def initialize(name)
      @name = name
    end

    # @abstract This method must be overriden in subclasses
    def load
      raise NotImplementedError
    end

    # @abstract This method must be overriden in subclasses
    def save
      raise NotImplementedError
    end

  end

end

require_relative 'io_plugins/file_io_plugin_mixin'
require_relative 'io_plugins/jwk_io_plugin_mixin'
require_relative 'io_plugins/openssl_io_plugin'
require_relative 'io_plugins/account_key'
require_relative 'io_plugins/key_file'
require_relative 'io_plugins/chain_file'
require_relative 'io_plugins/full_chain_file'
require_relative 'io_plugins/cert_file'
