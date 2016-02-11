require_relative 'spec_helper'

module LetsCert

  describe Loggable do

    it 'extend a class to add loggability' do
      class TestA; include Loggable; end

      expect(TestA.methods).to include(:logger=)

      my_logger = Logger.new(STDERR)
      TestA.logger = my_logger
      expect(TestA.new.logger).to eq(my_logger)
    end

    it 'extend a class and its subclasses to add loggability' do
      class TestA; include Loggable; end
      class TestB < TestA; end

      expect(TestA.methods).to include(:logger=)
      expect(TestB.methods).to include(:logger=)

      my_logger = Logger.new(STDERR)
      TestA.logger = my_logger
      expect(TestA.new.logger).to eq(my_logger)
      expect(TestB.new.logger).to eq(my_logger)
    end

  end

end
