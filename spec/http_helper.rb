module HttpHelper
  def serve_files_from(path)
    return yield unless VCR.real_http_connections_allowed?

    null_logger = Logger.new(StringIO.new)
    webrick = webrick = WEBrick::HTTPServer.new(Port: 5002, DocumentRoot: path,
                                                Logger: null_logger,
                                                AccessLog: null_logger)

    begin
      thread = Thread.new { webrick.start }

      yield
    ensure
      webrick.shutdown
      thread.join
    end
  end

end
