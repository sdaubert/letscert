module FileHelper

  def change_dir_to(new_dir)
    old_dir = FileUtils.pwd
    FileUtils.cd new_dir

    begin
    yield if block_given?
    ensure
      FileUtils.cd old_dir
    end
  end

  def ensure_file_is_deleted(file)
    yield
  ensure
    File.unlink file
  end
end

