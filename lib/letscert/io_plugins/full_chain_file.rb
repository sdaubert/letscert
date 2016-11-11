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

  # Fullchain file plugin
  # @author Sylvain Daubert
  class FullChainFile < ChainFile

    # @return [Hash] always get +true+ for +:cert+ and +:chain+ keys
    def persisted
      @persisted ||= { cert: true, chain: true }
    end

    # Load full certificate chain
    # @return [Hash]
    def load
      data = super
      if data[:chain].nil? or data[:chain].empty?
        cert = nil
        chain = []
      else
        cert = data[:chain].shift
        chain = data[:chain]
      end

      { cert: cert, chain: chain }
    end

    # Save fullchain.
    # @param [Hash] data
    # @return [void]
    def save(data)
      super(cert: nil, chain: [data[:cert]] + data[:chain])
    end

  end

  IOPlugin.register(FullChainFile, 'fullchain.pem'.freeze, :pem)
end
