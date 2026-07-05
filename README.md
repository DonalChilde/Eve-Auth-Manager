## Eve Auth Manager

Eve Auth Manager is a CLI and API-focused project for acquiring, storing,
retrieving, and refreshing OAuth tokens used with EVE Online ESI endpoints.

This project is in a usable beta state. All features are working, but the shapes
could change in the future.

## Features

- Manage ESI app credentials in a local auth database.
- Authorize characters and persist character token state.
- Refresh or revoke one or many character authorizations.
- Search EVE entity IDs through the ESI universe IDs endpoint - Look up character ids from names.
- Pipe authorization information to other apps as json.
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

### 1. Create credentials.json from EVE Developers

1. Go to https://developers.eveonline.com/applications and sign in.
2. Create a new ESI application (or open an existing one).
3. Copy the application JSON payload from the portal.
4. Save it locally as credentials.json.

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

### 6. Make an authorized ESI request from authorize output

You can make authenticated requests from the EVE Esi using the access token from the 
authorize command.

    NOTE: Access tokens have an expiration date. The below command gets a token good for the maximum time, 20 minutes.

```bash
uv run eve-auth authorize --cred-name <credential-name> --character-id <character-id> --indent 2 --min-seconds 1200
```

results in:

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

- `cred_id`: credential UUID used for the authorization.
- `character_id`: EVE character ID associated with the token.
- `character_name`: EVE character name from the validated token.
- `access_token`: bearer token to send in the Authorization header.
- `expires_at`: Unix timestamp, in seconds, when the access token expires.

You can copy and paste the access token with the [ESI Api Explorer](https://developers.eveonline.com/api-explorer) to view authenticated endpoints.

NOTE: Specific endpoints require specific scopes that were defined when you made the app credentials.


```bash
# A bash example using python to extract the needed info.
AUTH_JSON="$(uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id>)"
ACCESS_TOKEN="$(printf '%s' "$AUTH_JSON" | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")"
CHARACTER_ID="$(printf '%s' "$AUTH_JSON" | python -c "import sys, json; print(json.load(sys.stdin)['character_id'])")"

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
	"https://esi.evetech.net/characters/$CHARACTER_ID/attributes/?datasource=tranquility"
```

```bash
# A bash example piping JSON through jq
uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id> \
	| jq -r '"\(.access_token) \(.character_id)"' \
	| {
		read -r ACCESS_TOKEN CHARACTER_ID
		curl -H "Authorization: Bearer $ACCESS_TOKEN" \
			"https://esi.evetech.net/characters/$CHARACTER_ID/attributes/?datasource=tranquility"
	}
```

```bash
# A bash example saving JSON to a file and reading fields with jq
uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id> \
	> /tmp/eve-auth-authorized.json

ACCESS_TOKEN="$(jq -r '.access_token' /tmp/eve-auth-authorized.json)"
CHARACTER_ID="$(jq -r '.character_id' /tmp/eve-auth-authorized.json)"

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
	"https://esi.evetech.net/characters/$CHARACTER_ID/attributes/?datasource=tranquility"
```

```python
# A Python script that accepts piped AuthorizedDict JSON from stdin.
import json
import sys
from urllib.request import Request, urlopen


authorized = json.load(sys.stdin)
access_token = authorized["access_token"]
character_id = authorized["character_id"]

request = Request(
	url=(
		f"https://esi.evetech.net/characters/{character_id}/attributes/"
		"?datasource=tranquility"
	),
	headers={"Authorization": f"Bearer {access_token}"},
)

with urlopen(request) as response:
	print(response.read().decode("utf-8"))
```

```bash
# Example invocation for the Python script above
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
	url = (
		f"https://esi.evetech.net/characters/{character_id}/attributes/"
		"?datasource=tranquility"
	)

	with Client(headers={"Authorization": f"Bearer {access_token}"}) as client:
		response = client.get(url)
		response.raise_for_status()

	typer.echo(response.text)


if __name__ == "__main__":
	typer.run(main)
```

```bash
# Example invocation for the PEP 723 script above
uv run eve-auth authorize --cred-id <credential-uuid> --character-id <character-id> \
	| uv run ./esi_attributes_from_authorize.py
```





### 7. Display character authorizations

```bash
uv run eve-auth characters display --cred-id <credential-uuid>
```

### 8. Refresh character tokens

Refresh all for a credential:

```bash
uv run eve-auth characters refresh --cred-id <credential-uuid>
```

Refresh one character:

```bash
uv run eve-auth characters refresh --cred-id <credential-uuid> <character-id>
```

### 9. Revoke character authorizations

Revoke all authorized characters for a credential:

```bash
uv run eve-auth characters revoke --cred-id <credential-uuid>
```

Revoke specific characters:

```bash
uv run eve-auth characters revoke --cred-id <credential-uuid> --character-id <id1> --character-id <id2>
```

### 10. Search entity IDs

```bash
uv run eve-auth characters search --search Tritanium
```

### 11. Reset auth database

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
