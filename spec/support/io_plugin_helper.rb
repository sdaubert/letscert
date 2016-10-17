module IOPluginHelper

  class FakeIOPlugin < LetsCert::IOPlugin

    @@saved_data = {}

    def self.saved_data
      @@saved_data
    end

    def load(data)
      data
    end

    def save(data)
      @@saved_data = data
    end
  end
  LetsCert::IOPlugin.register(FakeIOPlugin, 'fake')

end
