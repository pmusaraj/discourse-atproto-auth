# frozen_string_literal: true

class EnableAtprotoValidator
  def initialize(opts = {})
    @opts = opts
  end

  def valid_value?(val)
    return true if val == "f"
    return false if SiteSetting.atproto_auth_private_key.blank?

    true
  end

  def error_message
    I18n.t("site_settings.errors.atproto_auth_private_key_is_blank")
  end
end
