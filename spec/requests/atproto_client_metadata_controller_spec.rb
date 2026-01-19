# frozen_string_literal: true

RSpec.describe AtprotoClientMetadataController do
  before do
    SiteSetting.atproto_auth_private_key = <<~PEM
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEII5QfARb2o8wdZT/Lg3wH91fL5aUQPExk+3ySnz2nzOtoAoGCCqGSM49
      AwEHoUQDQgAEOcsgacixOVdpZnAngStVr8DUXuGnD81WHTr+W6IfDLdZrxRgoU2w
      7gA6f55gou6olD9cm6GOtVxRo9g/B5qFkQ==
      -----END EC PRIVATE KEY-----
    PEM
    SiteSetting.atproto_auth_enabled = true
  end

  describe "#show" do
    it "returns client metadata JSON" do
      get "/oauth/client-metadata.json"

      expect(response.status).to eq(200)
      expect(response.content_type).to start_with("application/json")

      json = response.parsed_body

      expect(json["client_id"]).to eq("#{Discourse.base_url}/oauth/client-metadata.json")
      expect(json["client_name"]).to eq(SiteSetting.title)
      expect(json["client_uri"]).to eq(Discourse.base_url)
      expect(json["redirect_uris"]).to include("#{Discourse.base_url}/auth/atproto/callback")
      expect(json["grant_types"]).to eq(%w[authorization_code refresh_token])
      expect(json["response_types"]).to eq(%w[code])
      expect(json["token_endpoint_auth_method"]).to eq("private_key_jwt")
      expect(json["token_endpoint_auth_signing_alg"]).to eq("ES256")
      expect(json["dpop_bound_access_tokens"]).to eq(true)
      expect(json["application_type"]).to eq("web")
    end

    it "includes JWKS with public key" do
      get "/oauth/client-metadata.json"

      json = response.parsed_body
      jwks = json["jwks"]

      expect(jwks).to be_present
      expect(jwks["keys"]).to be_an(Array)
      expect(jwks["keys"].length).to eq(1)

      key = jwks["keys"].first
      expect(key["kty"]).to eq("EC")
      expect(key["crv"]).to eq("P-256")
      expect(key["use"]).to eq("sig")
      expect(key["alg"]).to eq("ES256")
      expect(key["kid"]).to be_present
      expect(key["d"]).to be_nil
    end

    it "sets cache headers" do
      get "/oauth/client-metadata.json"

      expect(response.headers["Cache-Control"]).to include("public")
      expect(response.headers["Cache-Control"]).to include("max-age=3600")
    end

    context "when private key is not configured" do
      before { SiteSetting.atproto_auth_private_key = "" }

      it "returns empty JWKS keys" do
        get "/oauth/client-metadata.json"

        json = response.parsed_body
        expect(json["jwks"]["keys"]).to eq([{}])
      end
    end
  end
end
