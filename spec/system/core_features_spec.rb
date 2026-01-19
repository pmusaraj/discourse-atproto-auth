# frozen_string_literal: true

RSpec.describe "Core features", type: :system do
  before do
    SiteSetting.atproto_auth_private_key =
      "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----"
    enable_current_plugin
  end

  it_behaves_like "having working core features"
end
