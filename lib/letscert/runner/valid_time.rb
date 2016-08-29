module LetsCert
  class Runner

    # Class used to process validation time from String.
    # @author Sylvain Daubert
    class ValidTime

      # @param [String] str time string. May be:
      #   * an integer -> time in seconds
      #   * an integer plus a letter:
      #     * 30m: 30 minutes,
      #     * 30h: 30 hours,
      #     * 30d: 30 days.
      def initialize(str)
        m = str.match(/^(\d+)([mhd])?$/)
        if m
          case m[2]
          when nil
            @seconds = m[1].to_i
          when 'm'
            @seconds = m[1].to_i * 60
          when 'h'
            @seconds = m[1].to_i * 60 * 60
          when 'd'
            @seconds = m[1].to_i * 24 * 60 * 60
          end
        else
          raise OptionParser::InvalidArgument, "invalid argument: --valid-min #{str}"
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
end
