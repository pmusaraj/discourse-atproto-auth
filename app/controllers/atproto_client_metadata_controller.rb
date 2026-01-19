# frozen_string_literal: true

class AtprotoClientMetadataController < ApplicationController
  requires_plugin "discourse-atproto-auth"

  skip_before_action :check_xhr
  skip_before_action :redirect_to_login_if_required
  skip_before_action :verify_authenticity_token

  def show
    client_id = client_metadata_url

    metadata = {
      client_id: client_id,
      client_name: SiteSetting.title,
      client_uri: Discourse.base_url,
      logo_uri: UrlHelper.absolute(SiteSetting.site_logo_url),
      redirect_uris: [oauth_callback_url],
      scope: "atproto transition:email",
      grant_types: %w[authorization_code refresh_token],
      response_types: %w[code],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      dpop_bound_access_tokens: true,
      application_type: "web",
      jwks: {
        keys: [public_jwk],
      },
    }

    response.headers["Cache-Control"] = "public, max-age=3600"
    render json: metadata
  end

  private

  def client_metadata_url
    "#{Discourse.base_url}/oauth/client-metadata.json"
  end

  def oauth_callback_url
    "#{Discourse.base_url}/auth/atproto/callback"
  end

  def public_jwk
    private_key_pem = SiteSetting.atproto_auth_private_key
    return {} if private_key_pem.blank?

    private_key = OpenSSL::PKey.read(private_key_pem)
    jwk = JWT::JWK.new(private_key)
    jwk_hash = jwk.export(include_private: false)
    jwk_hash[:kid] = jwk.kid
    jwk_hash[:use] = "sig"
    jwk_hash[:alg] = "ES256"
    pp jwk_hash
    jwk_hash
  end
end
