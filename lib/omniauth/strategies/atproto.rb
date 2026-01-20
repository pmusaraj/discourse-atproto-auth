# frozen_string_literal: true

require "omniauth-oauth2"
require "json"
require "faraday"

module OmniAuth
  module Strategies
    class Atproto < OmniAuth::Strategies::OAuth2
      option :name, "atproto"
      option :scope, "atproto transition:email"
      option :pkce, true
      option :authorization_server, "https://bsky.social"

      uid { @access_token.params["sub"] }

      info do
        {
          did: @access_token.params["sub"],
          email: @session_data&.dig("email"),
          email_confirmed: @session_data&.dig("emailConfirmed"),
          name: @profile_data&.dig("displayName").presence || @profile_data&.dig("handle"),
          nickname: @profile_data&.dig("handle"),
          image: @profile_data&.dig("avatar"),
        }
      end

      extra { { raw_info: @profile_data || {} } }

      def request_phase
        authorization_info = self.class.get_authorization_data(options[:authorization_server])

        session["omniauth.atproto.authorization_info"] = authorization_info

        options.client_options[:site] = authorization_info["issuer"]
        options.client_options[:authorize_url] = authorization_info["authorization_endpoint"]
        options.client_options[:token_url] = authorization_info["token_endpoint"]

        super
      end

      def callback_phase
        authorization_info = session.delete("omniauth.atproto.authorization_info")

        if authorization_info
          options.client_options[:site] = authorization_info["issuer"]
          options.client_options[:authorize_url] = authorization_info["authorization_endpoint"]
          options.client_options[:token_url] = authorization_info["token_endpoint"]
        else
          return fail!(:session_expired, OmniAuth::Error.new("Session expired - please try again"))
        end

        super
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

        url = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"

        response = Faraday.get(url) { |req| req.params["actor"] = did }

        if response.success?
          @profile_data = JSON.parse(response.body)
        else
          raise OmniAuth::Error, "Failed to load profile data: #{response.status}"
        end
      rescue StandardError => e
        Rails.logger.warn("ATProto: Failed to fetch profile data: #{e.message}")
        @profile_data = nil
      end

      def fetch_session_data
        did = @access_token.params["sub"]

        return unless did

        # Resolve DID to find PDS endpoint for session data
        resolver = DIDKit::Resolver.new
        did_doc = resolver.resolve_did(did)
        pds_endpoint = did_doc&.pds_endpoint

        return unless pds_endpoint

        url = "#{pds_endpoint}/xrpc/com.atproto.server.getSession"

        atproto_client =
          AtProto::Client.new(private_key: options[:private_key], access_token: @access_token.token)
        @session_data = atproto_client.request(:get, url)
      rescue StandardError => e
        Rails.logger.warn("ATProto: Failed to fetch session data: #{e.message}")
        @session_data = nil
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
