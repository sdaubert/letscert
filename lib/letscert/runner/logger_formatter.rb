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
  class Runner

    # Custom logger formatter
    class LoggerFormatter < Logger::Formatter

      # @private log format
      FORMAT = "[%s] %5s: %s\n".freeze

      # @private time format string
      TIME_FORMAT = '%Y-%m-%d %H:%M:%S'.freeze

      # @param [String] severity
      # @param [Datetime] time
      # @param [nil,String] _progname
      # @param [String] msg
      # @return [String]
      def call(severity, time, _progname, msg)
        FORMAT % [format_datetime(time), severity, msg2str(msg)]
      end

      private

      # @private simple datetime formatter
      # @param [DateTime] time
      # @return [String]
      def format_datetime(time)
        time.strftime TIME_FORMAT
      end

    end

  end
end
