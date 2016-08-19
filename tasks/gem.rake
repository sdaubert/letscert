require 'rubygems/package_task'
require_relative '../lib/letscert.rb'

spec = Gem::Specification.new do |s|
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

  files = Dir['{spec,lib,bin,tasks}/**/*']
  files += ['README.md', 'LICENSE', 'Rakefile']
  # For now, device is not in gem.
  s.files = files
  s.executables = ['letscert']

  s.required_ruby_version = '>= 2.1.0'

  s.add_dependency 'acme-client', '~>0.4.0'
  s.add_dependency 'json', '~>1.8.3'

  s.add_development_dependency 'rspec', '~>3.4'
  s.add_development_dependency 'vcr', '~>3.0'
  s.add_development_dependency 'faraday', '~>0.9'
  s.add_development_dependency 'yard', '~>0.8'
  s.add_development_dependency 'simplecov'

  s.cert_chain = [File.join(__dir__, '..', 'certs/gem-public_cert.pem')]
  s.signing_key = File.expand_path('~/.ssh/gem-private_key.pem')
end


Gem::PackageTask.new(spec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
end
