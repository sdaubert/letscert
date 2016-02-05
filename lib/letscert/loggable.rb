module LetsCert

  module Loggable

    # Hook called when {Loggable} is included in a class or a module.
    # This hook adds methods from {ClassMethods} as class methods to +mod+.
    # @param [Module] mod
    # @return [void]
    def self.included(mod)
      mod.extend(ClassMethods)
    end

    module ClassMethods

      # @private hook called a subclass is created.
      #  Take care of all subclasses to later properly set @logger class instance variable.
      # @param [Class] subclass
      # @return [void]
      def inherited(subclass)
        @@subclasses ||= []
        @@subclasses << subclass
      end

      # Set logger
      # @param [Logger] logger
      def logger=(logger)
        @logger = logger
        @@subclasses.each do |subclass|
          subclass.instance_variable_set(:@logger, logger)
        end
      end

    end

    # Get logger instance
    # @return [Logger]
    def logger
      @logger ||= self.class.instance_variable_get(:@logger)
    end

  end

end
