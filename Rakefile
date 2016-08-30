require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'yard'
require 'rubocop/rake_task'

RSpec::Core::RakeTask.new

YARD::Rake::YardocTask.new do |t|
  t.options = ['--no-private']
  t.files = ['lib/**/*.rb', '-', 'LICENSE']
end

RuboCop::RakeTask.new

task default: :spec
