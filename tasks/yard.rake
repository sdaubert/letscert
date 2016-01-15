require 'yard'

YARD::Rake::YardocTask.new do |t|
  t.options = ['--no-private']
  t.files = ['lib/**/*.rb']
end
