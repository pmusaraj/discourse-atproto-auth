# frozen_string_literal: true

require "omniauth-oauth2"
require "json"
require "faraday"

module OmniAuth
  module Strategies
    class Atproto < OmniAuth::Strategies::OAuth2
      option :name, "atproto"
      option :fields, %i[handle]
      option :scope, "atproto transition:email"
      option :pkce, true

      uid { @access_token.params["sub"] }

      info do
        {
          did: @access_token.params["sub"],
          pds_host: options.client_options[:site],
          email: @session_data&.dig("email"),
          email_confirmed: @session_data&.dig("emailConfirmed"),
          name: @profile_data&.dig("handle"),
          nickname: @profile_data&.dig("handle"),
          image: @profile_data&.dig("avatar"),
        }
      end

      extra { { raw_info: @profile_data || {} } }

      def request_phase
        handle = request.params["handle"]

        if handle.blank?
          return(
            Rack::Response.new(handle_form_html, 200, { "Content-Type" => "text/html" }).finish
          )
        end

        begin
          resolver = DIDKit::Resolver.new
          did = resolver.resolve_handle(handle)

          unless did
            return fail!(:unknown_handle, OmniAuth::Error.new("Handle did not resolve to a DID"))
          end

          did_doc = resolver.resolve_did(did)
          endpoint = did_doc.pds_endpoint

          auth_server = self.class.get_authorization_server(endpoint)

          authorization_info = self.class.get_authorization_data(auth_server)

          session["omniauth.atproto.authorization_info"] = authorization_info
          session["omniauth.atproto.handle"] = handle
          session["omniauth.atproto.pds_endpoint"] = endpoint

          options.client_options[:site] = authorization_info["issuer"]
          options.client_options[:authorize_url] = authorization_info["authorization_endpoint"]
          options.client_options[:token_url] = authorization_info["token_endpoint"]
        rescue StandardError => e
          return(
            fail!(
              :discovery_error,
              OmniAuth::Error.new("Failed to discover authorization server: #{e.message}"),
            )
          )
        end

        super
      end

      def callback_phase
        authorization_info = session.delete("omniauth.atproto.authorization_info")
        @pds_endpoint = session.delete("omniauth.atproto.pds_endpoint")

        if authorization_info
          options.client_options[:site] = authorization_info["issuer"]
          options.client_options[:authorize_url] = authorization_info["authorization_endpoint"]
          options.client_options[:token_url] = authorization_info["token_endpoint"]
        else
          return fail!(:session_expired, OmniAuth::Error.new("Session expired - please try again"))
        end

        result = super
        result
      end

      def build_access_token
        authorization_code = request.params["code"]
        code_verifier = session.delete("omniauth.pkce.verifier")

        token_params = {
          code: authorization_code,
          code_verifier: code_verifier,
          redirect_uri: "#{Discourse.base_url}/auth/atproto/callback",
          jwk: options[:client_jwk],
          client_id: options[:client_id],
          site: options.client_options[:site],
          endpoint: options.client_options[:token_url],
        }

        response =
          AtProto::Client.new(private_key: options[:private_key]).get_token!(**token_params)

        @access_token = ::OAuth2::AccessToken.from_hash(client, response)

        if @access_token.params["sub"]
          fetch_profile_data
          fetch_session_data
        end

        @access_token
      end

      private

      def fetch_profile_data
        did = @access_token.params["sub"]

        return unless did

        # Use public Bluesky API - profile data is public and doesn't require auth
        url = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"

        response = Faraday.get(url) { |req| req.params["actor"] = did }

        if response.success?
          @profile_data = JSON.parse(response.body)
        else
          raise OmniAuth::Error, "Failed load profile data: #{response.status}"
        end
      rescue StandardError => e
        @profile_data = nil
      end

      def fetch_session_data
        return unless @pds_endpoint

        # Fetch session data (includes email) using DPoP-authenticated request
        url = "#{@pds_endpoint}/xrpc/com.atproto.server.getSession"

        atproto_client =
          AtProto::Client.new(private_key: options[:private_key], access_token: @access_token.token)
        @session_data = atproto_client.request(:get, url)
      rescue StandardError
        @session_data = nil
      end

      def handle_form_html
        title = I18n.t("atproto.handle_form.title")
        heading = I18n.t("atproto.handle_form.heading")
        label = I18n.t("atproto.handle_form.label")
        placeholder = I18n.t("atproto.handle_form.placeholder")
        hint = I18n.t("atproto.handle_form.hint")
        continue_text = I18n.t("atproto.handle_form.continue")

        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>#{ERB::Util.html_escape(title)}</title>
            <style>
              body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
              .container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
              h1 { margin-top: 0; color: #0085ff; font-size: 1.5rem; }
              label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
              input[type="text"] { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
              button { width: 100%; padding: 0.75rem; background: #0085ff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 1rem; }
              button:hover { background: #0066cc; }
              .hint { color: #666; font-size: 0.875rem; margin-top: 0.5rem; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>#{ERB::Util.html_escape(heading)}</h1>
              <form method="post" action="#{callback_path.sub("/callback", "")}">
                <label for="handle">#{ERB::Util.html_escape(label)}</label>
                <input type="text" id="handle" name="handle" placeholder="#{ERB::Util.html_escape(placeholder)}" required>
                <p class="hint">#{ERB::Util.html_escape(hint)}</p>
                <button type="submit">#{ERB::Util.html_escape(continue_text)}</button>
              </form>
            </div>
          </body>
          </html>
        HTML
      end

      def self.get_authorization_server(pds_endpoint)
        response = Faraday.get("#{pds_endpoint}/.well-known/oauth-protected-resource")

        unless response.success?
          raise OmniAuth::Error, "Failed to get PDS authorization server: #{response.status}"
        end

        result = JSON.parse(response.body)
        auth_server = result.dig("authorization_servers", 0)

        raise OmniAuth::Error, "No authorization server found in response" unless auth_server

        auth_server
      end

      def self.get_authorization_data(issuer)
        response = Faraday.get("#{issuer}/.well-known/oauth-authorization-server")

        unless response.success?
          raise OmniAuth::Error, "Failed to get authorization server metadata: #{response.status}"
        end

        result = JSON.parse(response.body)

        unless result["issuer"] == issuer
          raise OmniAuth::Error, "Invalid metadata - issuer mismatch"
        end

        fields = %w[issuer authorization_endpoint token_endpoint]
        result.select { |k, _v| fields.include?(k) }
      end
    end
  end
end
