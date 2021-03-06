require_relative '../spec_helper'

module LetsCert

  describe FileIOPluginMixin do

    before(:all) { IOPlugin.logger = Logger.new('/dev/null') }

    class Test; include FileIOPluginMixin; end
    class Test2 < IOPlugin
      include FileIOPluginMixin
      def load_from_content(content); { test2: content }; end
      def save(data); save_to_file data[:test2]; end
    end

    let(:test) { Test2.new('test.fileioplugin') }

    it '#load loads data from a file' do
      change_dir_to File.dirname(__FILE__) do
        content = test.load
        expect(content).to eq({ test2: "This is a test!\n" })
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

    context '#save_to_file' do
      it 'save to file' do
        tmpfile = 'tmpfile43'
        content = nil

        change_dir_to File.dirname(__FILE__) do
          content = test.load
        end

        test2 = Test2.new(tmpfile)
        test2.save(content)
        expect(File.read(tmpfile)).to eq(content[:test2])

        File.unlink tmpfile if File.exist? tmpfile
      end

      it 'does not overwrite a file which content did not change' do
        change_dir_to File.dirname(__FILE__) do
          content = test.load
          mtime = File.stat(test.name).mtime
          test.save(content)
          expect(mtime).to eq(File.stat(test.name).mtime)
        end
      end
    end
  end
end
