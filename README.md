# discourse-atproto-auth

Enable authentication via AT Protocol (Bluesky) for Discourse.

This plugin allows users to log in to your Discourse forum using their Bluesky account. It implements the AT Protocol OAuth specification, supporting users from any PDS (Personal Data Server) in the AT Protocol network.

## Features

- Login with Bluesky accounts using OAuth 2.0 with PKCE and DPoP
- Support for any AT Protocol handle (e.g., `user.bsky.social` or custom domains)
- Automatic profile data fetching (avatar, display name)
- Email verification support (when users grant email permission)
- Connect existing Discourse accounts to Bluesky

## Installation

Follow the [standard plugin installation guide](https://meta.discourse.org/t/install-plugins-in-discourse/19157).

## Configuration

### 1. Generate a Private Key

The plugin requires an ES256 private key for signing OAuth requests. Generate one using OpenSSL:

```bash
openssl ecparam -genkey -name prime256v1 -noout
```

This will output a PEM-formatted private key. Copy the entire output including the `-----BEGIN EC PRIVATE KEY-----` and `-----END EC PRIVATE KEY-----` lines.

### 2. Configure Site Settings

Navigate to **Admin > Settings > Login** and configure:

1. **atproto auth private key**: Paste the full private key PEM you generated
2. **atproto auth enabled**: Enable this after setting the private key

## How It Works

When a user clicks "Login with Bluesky":

1. They enter their Bluesky handle (e.g., `alice.bsky.social`)
2. The plugin resolves the handle to a DID (Decentralized Identifier)
3. The user's PDS is discovered and the authorization server is located
4. The user is redirected to authorize the login
5. Upon authorization, the plugin fetches profile data and creates/links the account

## Permissions Requested

The plugin requests the following OAuth scopes:

- `atproto`: Basic AT Protocol access for authentication
- `transition:email`: Access to the user's email address (if they grant it)
