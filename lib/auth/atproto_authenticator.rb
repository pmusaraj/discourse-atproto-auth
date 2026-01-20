# frozen_string_literal: true

class Auth::AtprotoAuthenticator < ::Auth::ManagedAuthenticator
  def name
    "atproto"
  end

  def enabled?
    SiteSetting.atproto_auth_enabled
  end

  def register_middleware(omniauth)
    omniauth.provider :atproto,
                      setup:
                        lambda { |env|
                          strategy = env["omniauth.strategy"]
                          strategy.options[
                            :client_id
                          ] = "#{Discourse.base_url}/oauth/client-metadata.json"
                          strategy.options[:scope] = "atproto transition:email"
                          strategy.options[:private_key] = private_key
                          strategy.options[:client_jwk] = client_jwk
                          strategy.options[
                            :authorization_server
                          ] = SiteSetting.atproto_auth_authorization_server
                        }
  end

  def primary_email_verified?(auth_token)
    email = auth_token.dig(:info, :email)
    email_confirmed = auth_token.dig(:info, :email_confirmed)
    email.present? && email_confirmed == true
  end

  def can_connect_existing_user?
    true
  end

  def can_revoke?
    true
  end

  def match_by_email
    true
  end

  def after_authenticate(auth_token, existing_account: nil)
    result = super

    info = auth_token[:info]
    result.username ||= info[:nickname]&.split(".")&.first
    result.name ||= info[:name].presence || info[:nickname]
    result.email ||= info[:email]
    result.email_valid = info[:email_confirmed]

    result
  end

  private

  def private_key
    return nil if SiteSetting.atproto_auth_private_key.blank?

    OpenSSL::PKey.read(SiteSetting.atproto_auth_private_key)
  end

  def client_jwk
    return nil if SiteSetting.atproto_auth_private_key.blank?

    key = private_key
    return nil unless key

    jwk = JWT::JWK.new(key)
    jwk_hash = jwk.export(include_private: false)
    jwk_hash[:kid] = jwk.kid
    jwk_hash
  end
end
