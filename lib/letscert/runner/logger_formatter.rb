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
