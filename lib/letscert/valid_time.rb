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

  # Class used to process validation time from String.
  # @author Sylvain Daubert
  class ValidTime

    # Number of seconds in one minute
    SECONDS_IN_ONE_MINUTE = 60
    # Number of seconds in one hour
    SECONDS_IN_ONE_HOUR = 60 * 60
    # Number of seconds in one day
    SECONDS_IN_ONE_DAY = 24 * 60 * 60

    # Get time in words (e.g. xx days or xx hours)
    # @param [Integer] seconds
    # @return [String]
    def self.time_in_words(seconds)
      if seconds < SECONDS_IN_ONE_MINUTE
        '%u seconds' % seconds
      elsif seconds < SECONDS_IN_ONE_HOUR
        'about %u minutes' % (seconds / SECONDS_IN_ONE_MINUTE)
      elsif seconds < SECONDS_IN_ONE_DAY
        'about %u hours' % (seconds / SECONDS_IN_ONE_HOUR)
      else
        'about %u days' % (seconds / SECONDS_IN_ONE_DAY)
      end
    end

    # @param [String] str time string. May be:
    #   * an integer -> time in seconds
    #   * an integer plus a letter:
    #     * 30m: 30 minutes,
    #     * 30h: 30 hours,
    #     * 30d: 30 days.
    def initialize(str)
      m = str.match(/^(\d+)([mhd])?$/)
      if m
        @seconds = case m[2]
                   when nil
                     m[1].to_i
                   when 'm'
                     m[1].to_i * SECONDS_IN_ONE_MINUTE
                   when 'h'
                     m[1].to_i * SECONDS_IN_ONE_HOUR
                   when 'd'
                     m[1].to_i * SECONDS_IN_ONE_DAY
                   end
      else
        raise OptionParser::InvalidArgument,
              "invalid argument: valid-min #{str}"
      end
      @string = str
    end

    # Get time in seconds
    # @return [Integer]
    def to_seconds
      @seconds
    end

    # Get time as string
    # @return [String]
    def to_s
      @string
    end
  end
end
