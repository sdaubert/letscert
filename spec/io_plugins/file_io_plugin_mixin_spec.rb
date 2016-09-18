require_relative '../spec_helper'

module LetsCert

  describe FileIOPluginMixin do

    before(:all) { IOPlugin.logger = Logger.new('/dev/null') }

    class Test; include FileIOPluginMixin; end
    class Test2 < IOPlugin
      include FileIOPluginMixin
      def load_from_content(content); content; end
    end

    let(:test) { Test2.new('test.fileioplugin') }

    it '#load loads data from a file' do
      change_dir_to File.dirname(__FILE__) do
        content = test.load
        expect(content).to eq("This is a test!\n")
      end
    end

    it '#load returns an empty set when no file exists' do
      test.instance_eval { @name = 'nofilename' }
      content = test.load
      expect(content).to eq(IOPlugin.empty_data)
    end

    it '#load_from_content raises NotImplementedError' do
      expect { Test.new.load_from_content("a") }.to raise_error(NotImplementedError)
    end

    it '#save_to_file' do
      tmpfile = 'tmpfile43'
      content = nil

      change_dir_to File.dirname(__FILE__) do
        content = test.load
      end

      test2 = Test2.new(tmpfile)
      test2.save_to_file(content)

      expect(File.read(tmpfile)).to eq(content)

      File.unlink tmpfile if File.exist? tmpfile
    end
    
  end

end
