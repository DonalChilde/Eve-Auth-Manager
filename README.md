## Eve Auth Manager

Eve Auth Manager is a CLI and API-focused project for acquiring, storing,
retrieving, and refreshing OAuth tokens used with EVE Online ESI endpoints.

This repository is currently in an active refactor. Some workflows may be
incomplete while commands and internals are being stabilized.

## Features

- Manage ESI app credentials in a local auth database.
- Authorize characters and persist character token state.
- Refresh or revoke one or many character authorizations.
- Search EVE entity IDs through the ESI universe IDs endpoint - Look up character ids from names.
- Emit machine-friendly JSON payloads for integration workflows - pipe an authorization token as json.
- Reset and recreate the auth database for clean test/dev state.
- API offers an easy one context managed class for all operations except initial character authorization. Thats CLI only.

## Requirements

- Python 3.14 or newer
- uv

## Installation

### Option 1: uv-managed project environment (recommended)

1. Clone the repository.
2. Create or update the virtual environment and install dependencies.

```bash
git clone https://github.com/DonalChilde/Eve-Auth-Manager.git
cd Eve-Auth-Manager
uv sync
```

Run the CLI from the managed environment:

```bash
uv run eve-auth --help
```

### Option 2: Source install

Install the project from source into your active Python environment.

From a local checkout:

```bash
git clone https://github.com/DonalChilde/Eve-Auth-Manager.git
cd Eve-Auth-Manager
python -m pip install .
```

Or install in editable mode for local development:

```bash
python -m pip install -e .
```

Then run:

```bash
eve-auth --help
```

## Configuration

Settings can be loaded from environment variables with the prefix
ESI_AUTH_MANAGER_.

Supported setting keys:

- ESI_AUTH_MANAGER_AUTH_DB_PATH: path to the SQLite auth database file.

Default auth database location is platform-specific app data directory plus
auth_manager.db.

## Quick Start

### 1. Inspect top-level help

```bash
uv run eve-auth --help
```

### 2. Add ESI app credentials

From a JSON file:

```bash
uv run eve-auth credentials add --from ./credentials.json
```

From stdin:

```bash
cat ./credentials.json | uv run eve-auth credentials add --from -
```

Credential payload shape:

```json
{
	"name": "My ESI App",
	"description": "Optional human-readable description",
	"clientId": "your_client_id",
	"clientSecret": "your_client_secret",
	"callbackUrl": "http://localhost:8080/callback",
	"scopes": ["scope1", "scope2"]
}
```

### 3. Display credentials

Summary:

```bash
uv run eve-auth credentials display
```

Detailed by credential ID:

```bash
uv run eve-auth credentials display --cred-id <credential-uuid>
```

### 4. Authorize and add a character

```bash
uv run eve-auth characters add <character-id> --cred-id <credential-uuid>
```

### 5. Display character authorizations

```bash
uv run eve-auth characters display --cred-id <credential-uuid>
```

### 6. Refresh character tokens

Refresh all for a credential:

```bash
uv run eve-auth characters refresh --cred-id <credential-uuid>
```

Refresh one character:

```bash
uv run eve-auth characters refresh --cred-id <credential-uuid> <character-id>
```

### 7. Revoke character authorizations

Revoke all authorized characters for a credential:

```bash
uv run eve-auth characters revoke --cred-id <credential-uuid>
```

Revoke specific characters:

```bash
uv run eve-auth characters revoke --cred-id <credential-uuid> --character-id <id1> --character-id <id2>
```

### 8. Search entity IDs

```bash
uv run eve-auth characters search --search Tritanium
```

### 9. Reset auth database

```bash
uv run eve-auth util reset --force
```

## Command Groups

- authorize: refresh and emit an AuthorizedDict JSON payload.
- credentials: add, display, and remove ESI application credentials.
- characters: add, display, refresh, revoke, and search entity IDs.
- util: maintenance commands such as database reset.

## Development

Run tests:

```bash
uv run pytest
```

Format code:

```bash
uv run ruff format
```

Lint code:

```bash
uv run ruff check
```

## License

MIT. See LICENSE.
