"""HTTP session factory for Eve Auth Manager."""

from contextlib import asynccontextmanager, contextmanager

from httpx2 import AsyncClient, Client

from eve_auth_manager.settings import USER_AGENT


def config_http_client(user_agent: str = USER_AGENT) -> Client:
    """Configures the HTTP client with the provided user agent.

    It is the caller's responsibility to close the client when done.
    """
    return Client(headers={"User-Agent": user_agent})


async def config_async_http_client(user_agent: str = USER_AGENT) -> AsyncClient:
    """Configures the asynchronous HTTP client with the provided user agent.

    It is the caller's responsibility to close the client when done.
    """
    return AsyncClient(headers={"User-Agent": user_agent})


@contextmanager
def client_manager(user_agent: str = USER_AGENT):
    """Context manager for the HTTP client."""
    client: Client | None = None
    try:
        client = config_http_client(user_agent)
        yield client
    finally:
        if client is not None:
            client.close()


@asynccontextmanager
async def async_client_manager(user_agent: str = USER_AGENT):
    """Context manager for the asynchronous HTTP client."""
    client: AsyncClient | None = None
    try:
        client = await config_async_http_client(user_agent)
        yield client
    finally:
        if client is not None:
            await client.aclose()
