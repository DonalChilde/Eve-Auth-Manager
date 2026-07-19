-- SQLite schema for Eve Auth Manager persistence.
-- Stores credential records, authorized character records, and a singleton
-- cache of OAuth metadata. JSON-like application payloads are stored as TEXT,
-- and timestamps are stored as INTEGER Unix epoch values.

-- Stores EVE SSO client credentials managed by the application.
CREATE TABLE IF NOT EXISTS credentials (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cred_id TEXT NOT NULL UNIQUE, -- Application credential identifier.
    name TEXT NOT NULL UNIQUE, -- Human-readable name associated with the credential.
    description TEXT, -- Brief description of the credential.
    client_id TEXT NOT NULL, -- EVE Online SSO client ID.
    client_secret TEXT NOT NULL, -- EVE Online SSO client secret.
    callback_url TEXT NOT NULL, -- Registered EVE Online SSO callback URL.
    scopes TEXT NOT NULL, -- Requested OAuth scopes serialized as a JSON array string.
    created_at INTEGER NOT NULL -- Creation time as a Unix epoch timestamp.
);

-- Stores per-character authorization state linked to a credential.
CREATE TABLE IF NOT EXISTS authorized_characters (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cred_id TEXT NOT NULL, -- Application credential identifier.
    character_id INTEGER NOT NULL, -- EVE character identifier.
    character_name TEXT NOT NULL, -- EVE character name.
    expires_at INTEGER NOT NULL, -- Authorization expiration as a Unix epoch timestamp.
    oauth_token TEXT NOT NULL, -- OAuth token payload serialized as a JSON string.
    FOREIGN KEY (cred_id) REFERENCES credentials (cred_id) ON DELETE CASCADE,
    -- Enforce at most one row per credential/character pair.
    UNIQUE (cred_id, character_id)
);

-- Stores a singleton cache of OAuth metadata fetched from the provider.
-- The table is constrained to a single row with row_id = 1.
CREATE TABLE IF NOT EXISTS oauth_metadata (
    row_id INTEGER PRIMARY KEY DEFAULT 1, -- Singleton row identifier.
    created_at INTEGER NOT NULL, -- Cache creation time as a Unix epoch timestamp.
    oauth_metadata TEXT NOT NULL, -- Cached OAuth metadata serialized as a JSON string.
    CONSTRAINT single_row CHECK (row_id = 1) -- Enforce the singleton row invariant.
);