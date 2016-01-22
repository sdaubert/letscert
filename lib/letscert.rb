# Namespace for all letcert's classes.
module LetsCert

  # Letscert version number
  VERSION = '0.2.0'


  # Base error class
  class Error < StandardError; end

end

require_relative 'letscert/runner'
