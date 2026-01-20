# frozen_string_literal: true

# name: discourse-atproto-auth
# about: Discourse authentication via AT Protocol (Bluesky)
# version: 0.2.0
# authors: Penar Musaraj, Claude Code
# url: https://github.com/pmusaraj/discourse-atproto-auth

gem "didkit", "0.3.1"
gem "atproto_client", "0.1.4"

enabled_site_setting :atproto_auth_enabled

register_svg_icon "fab-bluesky"

require_relative "lib/omniauth/strategies/atproto"
require_relative "lib/auth/atproto_authenticator"
require_relative "lib/validators/enable_atproto_validator"

auth_provider authenticator: Auth::AtprotoAuthenticator.new, icon: "fab-bluesky"

after_initialize do
  require_relative "app/controllers/atproto_client_metadata_controller"

  Discourse::Application.routes.prepend do
    get "/oauth/client-metadata.json" => "atproto_client_metadata#show"
  end
end
