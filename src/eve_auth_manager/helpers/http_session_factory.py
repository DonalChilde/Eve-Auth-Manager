from httpx2 import AsyncClient, Client

from eve_auth_manager.settings import USER_AGENT


def config_http_client(user_agent: str = USER_AGENT) -> Client:
    """Configures the HTTP client with the provided user agent."""
    return Client(headers={"User-Agent": user_agent})


async def config_async_http_client(user_agent: str = USER_AGENT) -> AsyncClient:
    """Configures the asynchronous HTTP client with the provided user agent."""
    return AsyncClient(headers={"User-Agent": user_agent})
