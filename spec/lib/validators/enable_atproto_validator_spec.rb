# frozen_string_literal: true

RSpec.describe EnableAtprotoValidator do
  subject(:validator) { described_class.new }

  describe "#valid_value?" do
    describe "when atproto_auth_private_key has not been set" do
      it "should return true when value is false" do
        expect(validator.valid_value?("f")).to eq(true)
      end

      it "should return false when value is true" do
        expect(validator.valid_value?("t")).to eq(false)

        expect(validator.error_message).to eq(
          I18n.t("site_settings.errors.atproto_auth_private_key_is_blank"),
        )
      end
    end

    describe "when atproto_auth_private_key has been set" do
      before do
        SiteSetting.atproto_auth_private_key =
          "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----"
      end

      it "should return true when value is false" do
        expect(validator.valid_value?("f")).to eq(true)
      end

      it "should return true when value is true" do
        expect(validator.valid_value?("t")).to eq(true)
      end
    end
  end
end
