# frozen_string_literal: true

RSpec.describe "AT Protocol Associated Account Preferences", type: :system do
  fab!(:user)

  let!(:user_account_preferences_page) { PageObjects::Pages::UserPreferencesAccount.new }

  before do
    SiteSetting.atproto_auth_private_key =
      "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----"
    enable_current_plugin
  end

  it "shows the connect button" do
    sign_in(user)
    user_account_preferences_page.visit(user)
    expect(page).to have_css(".associated-accounts .atproto")
    expect(page).to have_css(".associated-accounts .atproto .associated-account__actions button")
    expect(find(".associated-accounts .atproto .associated-account__actions button")).to have_text(
      I18n.t("js.user.associated_accounts.connect"),
    )
  end

  describe "with already associated account" do
    fab!(:user_associated_account) do
      UserAssociatedAccount.create!(
        provider_name: "atproto",
        provider_uid: "did:plc:example123",
        user_id: user.id,
      )
    end

    it "shows the revoke button" do
      sign_in(user)
      user_account_preferences_page.visit(user)
      expect(page).to have_css(".associated-accounts .atproto")
      expect(page).to have_css(".associated-accounts .atproto .associated-account__actions button")
      expect(page).to have_css(
        ".associated-accounts .atproto .associated-account__actions button svg.d-icon-trash-can",
      )
    end
  end
end
