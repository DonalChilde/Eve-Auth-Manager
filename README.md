## Eve Auth Manager

Eve Auth Manager is a CLI-first tool for acquiring, storing, retrieving,
refreshing, and revoking EVE Online ESI OAuth tokens.

It stores ESI application credentials and authorized character state in a local
SQLite database, and can emit fresh authorization payloads for use by other
tools and scripts.

The current command set is feature-stable for this version. Documentation and
usability improvements are still ongoing.

## Features

- Store ESI application credentials in a local SQLite auth database.
- Add and manage authorized EVE characters.
- Refresh or revoke one character or all characters for a credential.
- Search character IDs from names using the ESI universe IDs endpoint.
- Emit authorization JSON for other scripts and applications.
- Reset and recreate the auth database for clean development or test state.
- Use the SQLite-backed auth manager API for programmatic operations after
  initial CLI authorization.

## Requirements

- Python 3.14 or newer
- uv

## Installation

### Option 1: uv-managed project environment

Clone the repository and install the project plus development dependencies:

```bash
git clone https://github.com/DonalChilde/Eve-Auth-Manager.git
cd Eve-Auth-Manager
uv sync
```

Run the CLI with:

```bash
uv run eve-auth --help
```

### Option 2: Install from source

Install the project into your current Python environment:

```bash
git clone https://github.com/DonalChilde/Eve-Auth-Manager.git
cd Eve-Auth-Manager
python -m pip install .
```

For local development, editable install is also supported:

```bash
python -m pip install -e .
```

Then run:

```bash
eve-auth --help
```

## Configuration

Settings are loaded from environment variables prefixed with
`ESI_AUTH_MANAGER_`.

Supported settings:

- `ESI_AUTH_MANAGER_AUTH_DB_PATH`: Path to the SQLite auth database file.

By default, the auth database is created in the platform-specific application
data directory as `auth_manager.db`. Log files are written in a sibling
`logs` directory.

## CLI Overview

Top-level commands:

- `authorize`: Refresh a selected character if needed and emit an
  `AuthorizedDict` JSON payload.
- `credentials`: Add, display, and remove stored ESI application credentials.
- `characters`: Add, display, refresh, revoke, and search character
  authorizations.
- `util`: Maintenance commands such as database reset.

## Quick Start

### 1. Create `credentials.json` from EVE Developers

1. Go to https://developers.eveonline.com/applications and sign in.
2. Create a new ESI application, or open an existing one.
3. Copy the application JSON payload from the portal.
4. Save it locally as `credentials.json`.

Expected JSON shape:

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

### 2. Inspect top-level help

```bash
uv run eve-auth --help
```

### 3. Add ESI app credentials

From a JSON file:

```bash
uv run eve-auth credentials add --from ./credentials.json
```

From stdin:

```bash
cat ./credentials.json | uv run eve-auth credentials add --from -
```

### 4. Display credentials

Summary:

```bash
uv run eve-auth credentials display
```

Detailed by credential ID:

```bash
uv run eve-auth credentials display --cred-id <credential-uuid>
```

### 5. Authorize and add a character

```bash
uv run eve-auth characters add <character-id> --cred-id <credential-uuid>
# or
uv run eve-auth characters add <character-id> --cred-name <credential-name>
```

### 6. Get an authorization payload

Use `authorize` to refresh a character if needed and emit an `AuthorizedDict`
JSON payload.

```bash
uv run eve-auth authorize --cred-name <credential-name> --character-id <character-id> --indent 2 --min-seconds 1200
```

`--min-seconds 1200` requests refresh behavior for the maximum supported token
lifetime window before a refresh is skipped.

Example output:

```json
{
  "cred_id": "credential UUID as a string",
  "character_id": 123456789,
  "character_name": "Character Name",
  "access_token": "ESI bearer token",
  "expires_at": 1735689600
}
```

Field meanings:

- `cred_id`: Credential UUID used for the authorization.
- `character_id`: EVE character ID associated with the token.
- `character_name`: EVE character name from the validated token.
- `access_token`: Bearer token to send in the `Authorization` header.
- `expires_at`: Unix timestamp, in seconds, when the access token expires.

You can paste the access token into the
[ESI API Explorer](https://developers.eveonline.com/api-explorer) to explore
authenticated endpoints.

Specific endpoints require scopes that were granted when the application
credentials were created.

### 7. Use the authorization payload in shell scripts

```bash
# Extract fields with Python.
AUTH_JSON="$(uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id>)"
ACCESS_TOKEN="$(printf '%s' "$AUTH_JSON" | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")"
CHARACTER_ID="$(printf '%s' "$AUTH_JSON" | python -c "import sys, json; print(json.load(sys.stdin)['character_id'])")"
USER_AGENT="eve-auth-manager-readme-example/0.1"

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
	-H "User-Agent: $USER_AGENT" \
	"https://esi.evetech.net/characters/$CHARACTER_ID/attributes/?datasource=tranquility"
```

```bash
# Extract fields with jq.
uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id> \
	| jq -r '"\(.access_token) \(.character_id)"' \
	| {
			read -r ACCESS_TOKEN CHARACTER_ID
			USER_AGENT="eve-auth-manager-readme-example/0.1"
			curl -H "Authorization: Bearer $ACCESS_TOKEN" \
				-H "User-Agent: $USER_AGENT" \
				"https://esi.evetech.net/characters/$CHARACTER_ID/attributes/?datasource=tranquility"
		}
```

```bash
# Save output to a file and read it later.
uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id> \
	> /tmp/eve-auth-authorized.json

ACCESS_TOKEN="$(jq -r '.access_token' /tmp/eve-auth-authorized.json)"
CHARACTER_ID="$(jq -r '.character_id' /tmp/eve-auth-authorized.json)"
USER_AGENT="eve-auth-manager-readme-example/0.1"

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
	-H "User-Agent: $USER_AGENT" \
	"https://esi.evetech.net/characters/$CHARACTER_ID/attributes/?datasource=tranquility"
```

### 8. Use the authorization payload in Python

```python
# A Python script that accepts piped AuthorizedDict JSON from stdin.
import json
import sys
from urllib.request import Request, urlopen


authorized = json.load(sys.stdin)
access_token = authorized["access_token"]
character_id = authorized["character_id"]
user_agent = "eve-auth-manager-readme-example/0.1"

request = Request(
    url=(
        f"https://esi.evetech.net/characters/{character_id}/attributes/"
        "?datasource=tranquility"
    ),
    headers={"Authorization": f"Bearer {access_token}", "User-Agent": user_agent},
)

with urlopen(request) as response:
    print(response.read().decode("utf-8"))
```

```bash
# Example invocation for the Python script above.
uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id> \
	| python ./esi_attributes_from_authorize.py
```

```python
# A PEP 723 Python script that accepts piped AuthorizedDict JSON from stdin.
# /// script
# requires-python = ">=3.14"
# dependencies = [
#   "httpx2>=2.5.0",
#   "typer>=0.26.8",
# ]
# ///

import json
import sys

import typer
from httpx2 import Client


def main() -> None:
    authorized = json.load(sys.stdin)
    access_token = authorized["access_token"]
    character_id = authorized["character_id"]
    user_agent = "eve-auth-manager-readme-example/0.1"
    url = (
        f"https://esi.evetech.net/characters/{character_id}/attributes/"
        "?datasource=tranquility"
    )
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": user_agent}
    with Client(headers=headers) as client:
        response = client.get(url)
        response.raise_for_status()

    typer.echo(response.text)


if __name__ == "__main__":
    typer.run(main)
```

```bash
# Example invocation for the PEP 723 script above.
uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id> \
	| uv run ./esi_attributes_from_authorize.py
```

### 9. Display character authorizations

```bash
uv run eve-auth characters display --cred-id <credential-uuid>
```

### 10. Refresh character tokens

Refresh all for a credential:

```bash
uv run eve-auth characters refresh --cred-id <credential-uuid>
```

Refresh one character:

```bash
uv run eve-auth characters refresh --cred-id <credential-uuid> <character-id>
```

### 11. Revoke character authorizations

Revoke all authorized characters for a credential:

```bash
uv run eve-auth characters revoke --cred-id <credential-uuid>
```

Revoke specific characters:

```bash
uv run eve-auth characters revoke --cred-id <credential-uuid> --character-id <id1> --character-id <id2>
```

### 12. Search character IDs

```bash
uv run eve-auth characters search --search Tritanium
```

### 13. Reset the auth database

```bash
uv run eve-auth util reset --force
```

## Using the API

Most programmatic operations are available through the SQLite-backed auth
manager after credentials and characters have been added.

```python
from pathlib import Path

from eve_auth_manager.sqlite.manager import SqliteAuthManager


db_path = Path("./auth_manager.db")

with SqliteAuthManager(db_path) as auth_manager:
    credential = auth_manager.get_credential(cred_name="my-app")
    characters = auth_manager.get_all_characters(credential.cred_id)

print([character.character_name for character in characters])
```

## Development

Set up the project:

```bash
uv sync
```

Run tests:

```bash
uv run pytest
```

Run coverage for the package:

```bash
uv run pytest tests/eve_auth_manager --cov=src/eve_auth_manager --cov-report=term-missing
```

Check formatting and linting:

```bash
uv run ruff format --check
uv run ruff check
```

Format Python files:

```bash
uv run ruff format
```

## Testing

The automated test suite currently covers the full `src/eve_auth_manager`
package with complete statement and branch coverage.

## License

MIT. See `LICENSE`.
