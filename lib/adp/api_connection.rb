require 'uri'
require 'net/https'
require 'base64'
require 'json'

require_relative 'connection_configuration'
require_relative 'access_token'
require_relative 'connection_exception'
require_relative 'api_connection'
require_relative 'client_credential_configuration'
require_relative 'authorization_code_configuration'
require_relative 'connection/version'

module Adp
  module Connection
    class ApiConnection
      attr_accessor :connection_configuration
      attr_accessor :token_expiration
      attr_accessor :state
      attr_accessor :access_token

      # @param [Object] config
      def initialize(config = nil)
        self.connection_configuration = config
      end

      def connect
        if connection_configuration.nil?
          raise ConnectionException, 'Configuration is empty or not found'
        end

        self.access_token = get_access_token
      end

      def disconnect
        self.access_token = nil
      end

      # @return [Boolean]
      def is_connected_indicator?
        is_connected = false

        unless access_token.nil?
          # valid token to check if expired
          is_connected = true if Time.new < access_token.expires_on
        end

        is_connected
      end

      def get_access_token
        token = access_token
        result = nil

        if is_connected_indicator?

          if connection_configuration.nil?
            raise ConnectionException, 'Config error: Configuration is empty or not found'
          end
          if connection_configuration.grantType.nil?
            raise ConnectionException, 'Config error: Grant Type is empty or not known'
          end
          if connection_configuration.tokenServerURL.nil?
            raise ConnectionException, 'Config error: tokenServerURL is empty or not known'
          end
          if connection_configuration.clientID.nil?
            raise ConnectionException, 'Config error: clientID is empty or not known'
          end
          if connection_configuration.clientSecret.nil?
            raise ConnectionException, 'Config error: clientSecret is empty or not known'
          end
        end

        data = {
          'client_id' => connection_configuration.clientID,
          'client_secret' => connection_configuration.clientSecret,
          'grant_type' => connection_configuration.grantType
        }

        result = send_web_request(connection_configuration.tokenServerURL, data)

        if result['error'].nil?
          token = AccessToken.new(result)
        else
          raise ConnectionException, "Connection error: #{result['error_description']}"
        end

        token
      end

      # @return [Object]
      def get_adp_data(product_url)
        raise ConnectionException, "Connection error: can't get data, not connected" if access_token.nil? || !is_connected_indicator?

        authorization = "#{access_token.token_type} #{access_token.token}"

        data = {
          'client_id' => connection_configuration.clientID,
          'client_secret' => connection_configuration.clientSecret,
          'grant_type' => connection_configuration.grantType,
          'code' => connection_configuration.authorizationCode,
          'redirect_uri' => connection_configuration.redirectURL
        }

        data = send_web_request(product_url, data, authorization, 'application/json', 'GET')

        raise ConnectionException, "Connection error: #{data['error']}, #{data['error_description']}" unless data['error'].nil?

        data
      end

      def send_web_request(url, data = {}, authorization = nil, content_type = nil, method = nil)
        data ||= {}
        content_type ||= 'application/x-www-form-urlencoded'
        method ||= 'POST'

        log = Logger.new(STDOUT)
        log.level = Logger::DEBUG
        log.debug("URL: #{url}")
        log.debug("Client ID: #{data['client_id']}")
        log.debug("Client Secret: #{data['client_secret']}")
        log.debug("Grant Type: #{data['grant_type']}")

        useragent = "adp-connection-ruby/#{Adp::Connection::VERSION}"
        uri = URI.parse(url)
        pem = File.read(connection_configuration.sslCertPath.to_s)
        key = File.read(connection_configuration.sslKeyPath)
        http = Net::HTTP.new(uri.host, uri.port)

        log.debug("User agent: #{useragent}")

        unless connection_configuration.sslCertPath.nil?
          http.use_ssl = true
          http.cert = OpenSSL::X509::Certificate.new(pem)
          http.key = OpenSSL::PKey::RSA.new(key, connection_configuration.sslKeyPass)
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        end

        unless connection_configuration.sslCaPath.nil?
          http.cert_store = OpenSSL::X509::Store.new
          http.cert_store.add_file(connection_configuration.sslCaPath)
        end

        if method.eql?('POST')
          request = Net::HTTP::Post.new(uri.request_uri)
          request.set_form_data(data)
        else
          request = Net::HTTP::Get.new(uri.request_uri)
        end

        request.initialize_http_header('User-Agent' => useragent)

        request['Content-Type'] = content_type

        # add credentials if available
        request['Authorization'] = authorization unless authorization.nil?

        response = JSON.parse(http.request(request).body)
      end
    end
  end
end
