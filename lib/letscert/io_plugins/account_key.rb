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

  # Account key IO plugin
  # @author Sylvain Daubert
  class AccountKey < IOPlugin
    include FileIOPluginMixin
    include JWKIOPluginMixin

    # @return [Hash] always get +true+ for +:account_key+ key
    def persisted
      { account_key: true }
    end

    # @return [Hash]
    def load_from_content(content)
      { account_key: load_jwk(content) }
    end

    # Save account key.
    # @param [Hash] data
    # @return [void]
    def save(data)
      save_to_file(dump_jwk(data[:account_key]))
    end

  end

  IOPlugin.register(AccountKey, 'account_key.json')
end
