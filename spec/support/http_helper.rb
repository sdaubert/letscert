module HttpHelper
  def serve_files_from(path)
    return yield unless VCR.real_http_connections_allowed?

    null_logger = Logger.new(StringIO.new)
    webrick = WEBrick::HTTPServer.new(Port: 5002, DocumentRoot: path,
                                      Logger: null_logger, AccessLog: null_logger)

    begin
      thread = Thread.new { webrick.start }
      yield
    ensure
      webrick.shutdown
      thread.join
    end
  end

  # Faraday Middleware to remove HTTP-01 challenge
  class RemoveHttp01Middleware < Faraday::Middleware
    def call(request_env)
      @app.call(request_env).on_complete do |response_env|
        body = response_env.response.body
        if body['challenges'] and !body['challenges'].empty?
          body['challenges'].each_with_index do |challenge, index|
            if challenge['type'] == 'http-01'
              body['challenges'].delete_at(index)
              break
            end
          end
        end
      end
    end
  end
end
