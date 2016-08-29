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

# Namespace for all letcert's classes.
# @author Sylvain Daubert
module LetsCert

  # Mixin module to add loggability to a class.
  # @author Sylvain Daubert
  module Loggable

    # Hook called when {Loggable} is included in a class or a module.
    # This hook adds methods from {ClassMethods} as class methods to +mod+.
    # @param [Module] mod
    # @return [void]
    def self.included(mod)
      mod.extend(ClassMethods)
    end

    # Class methods from {Loggable} module to include in target classes.
    # @author Sylvain Daubert
    module ClassMethods

      # @private hook called when a subclass is created.
      #  Take care of all subclasses to later properly set @logger class
      #  instance variable.
      # @param [Class] subclass
      # @return [void]
      def inherited(subclass)
        @@subclasses ||= []
        @@subclasses << subclass
      end

      # Set logger
      # @param [Logger] logger
      # @return [void]
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
