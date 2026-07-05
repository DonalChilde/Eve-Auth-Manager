-- Table definitions for the Eve Auth Manager database schema.

-- This table represents the credentials used to authenticate with the EVE Online SSO.
CREATE TABLE IF NOT EXISTS credentials (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cred_id TEXT NOT NULL UNIQUE, -- The unique identifier for the credentials.
    name TEXT NOT NULL, -- The name associated with the credentials.
    description TEXT, -- A brief description of the credentials.
    client_id TEXT NOT NULL, -- The client ID for the EVE Online SSO.
    client_secret TEXT NOT NULL, -- The client secret for the EVE Online SSO.
    callback_url TEXT NOT NULL, -- The callback URL for the EVE Online SSO.
    scopes TEXT NOT NULL, -- The array of scopes requested for the EVE Online SSO as a JSON string.
    created_at INTEGER NOT NULL -- The timestamp when the credentials were created.
);

-- This table represents the authorized characters associated with the credentials.
CREATE TABLE IF NOT EXISTS authorized_characters (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cred_id TEXT NOT NULL, -- The unique identifier for the credentials.
    character_id INTEGER NOT NULL, -- The unique identifier for the character.
    character_name TEXT NOT NULL, -- The name of the character.
    expires_at INTEGER NOT NULL, -- The timestamp when the authorization expires.
    oauth_token TEXT NOT NULL, -- The OAuth token for the character as a JSON string.
    FOREIGN KEY (cred_id) REFERENCES credentials (cred_id) ON DELETE CASCADE,
    -- there can only be one cred_id/character_id pair in this table, so we can use a unique constraint to enforce that
    UNIQUE (cred_id, character_id)
);

-- This table represents the OauthMetadata cached for the credentials and characters.
-- There can be only one row in this table, and it will be updated whenever the 
-- OauthMetadata is refreshed.
CREATE TABLE IF NOT EXISTS oauth_metadata (
    row_id INTEGER PRIMARY KEY DEFAULT 1, -- There can only be one row in this table.
    created_at INTEGER NOT NULL, -- The timestamp when the metadata was created.
    oauth_metadata TEXT NOT NULL -- The OauthMetadata as a JSON string.
    CONSTRAINT single_row CHECK (row_id = 1) -- Enforce that there can only be one row in this table.
);