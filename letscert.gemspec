lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'letscert/version'

Gem::Specification.new do |s|
  s.name = 'letscert'
  s.version = LetsCert::VERSION
  s.license = 'MIT'
  s.summary = "letscert, a simple Let's Encrypt client"
  s.description = <<-EOF
letscert is a simple Let's Encrypt client written in Ruby. It aims at be as clean as
simp_le.
EOF

  s.authors << 'Sylvain Daubert'
  s.email = 'sylvain.daubert@laposte.net'
  s.homepage = 'https://github.com/sdaubert/letscert'

  s.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  s.executables = ['letscert']
  s.require_paths = ["lib"]

  s.required_ruby_version = '>= 2.1.0'

  s.add_dependency 'acme-client', '~>0.4.0'
  s.add_dependency 'json', '~>1.8.3'

  s.add_development_dependency "bundler", "~> 1.12"
  s.add_development_dependency "rake", "~> 10.0"
  s.add_development_dependency 'rspec', '~>3.4'
  s.add_development_dependency 'vcr', '~>3.0'
  s.add_development_dependency 'yard', '~>0.8'
  s.add_development_dependency 'simplecov', '~>0.12'
end
